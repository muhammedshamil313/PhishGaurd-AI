"""
analyzer.py
===========
Core symmetry analysis engine for Symmetry-Based Phishing Guard.
Uses Selenium for live DOM geometry + BeautifulSoup for CSS extraction.
"""

import re
import time
import math
import json
from dataclasses import dataclass, field, asdict
from typing import Optional

from bs4 import BeautifulSoup

# ── Selenium is an optional runtime dep (needed on target machine) ──────────
try:
    from selenium import webdriver
    from selenium.webdriver.chrome.options import Options
    from selenium.webdriver.chrome.service import Service
    from selenium.webdriver.common.by import By
    from selenium.webdriver.support.ui import WebDriverWait
    from selenium.webdriver.support import expected_conditions as EC
    from selenium.common.exceptions import TimeoutException, WebDriverException
    SELENIUM_AVAILABLE = True
except ImportError:
    SELENIUM_AVAILABLE = False


# ── Data classes ──────────────────────────────────────────────────────────────

@dataclass
class ContainerMetrics:
    index: int
    tag: str
    id: str
    classes: str
    # Geometry (px)
    x: float
    y: float
    width: float
    height: float
    viewport_width: float
    # Margins
    left_margin: float
    right_margin: float
    # Symmetry
    symmetry_ratio: float        # R = left_margin / right_margin
    deviation_pct: float         # |R - 1.0| * 100
    child_misalign_pct: float    # % of child inputs/buttons misaligned
    css_margin_left: float
    css_margin_right: float
    css_padding_left: float
    css_padding_right: float
    # Scores
    composite_score: float       # 0-100
    risk_level: str              # LOW / MEDIUM / HIGH


@dataclass
class PageReport:
    url: str
    title: str
    timestamp: float
    has_login_form: bool
    overall_risk: str            # LOW / MEDIUM / HIGH / NONE
    composite_score: float
    containers: list = field(default_factory=list)
    # Extra page-level signals
    domain: str = ""
    uses_https: bool = False
    has_favicon: bool = False
    login_keyword_in_url: bool = False
    ip_address_url: bool = False
    error: Optional[str] = None
    # Brand comparison fields
    detected_brand: str = ""
    original_url: str = ""
    original_title: str = ""
    original_containers: list = field(default_factory=list)
    comparison: dict = field(default_factory=dict)
    clone_verdict: str = ""   # CLONE / LIKELY_CLONE / CLEAN / UNKNOWN

    def to_dict(self):
        d = asdict(self)
        d["containers"] = [asdict(c) for c in self.containers]
        d["original_containers"] = [asdict(c) if hasattr(c, '__dataclass_fields__') else c for c in self.original_containers]
        return d


# ── Selenium driver factory ───────────────────────────────────────────────────

def build_driver(headless: bool = True, chromedriver_path: Optional[str] = None) -> "webdriver.Chrome":
    """
    Create a headless Chrome WebDriver.
    Install chromedriver: https://chromedriver.chromium.org/downloads
    Or use: pip install webdriver-manager
    """
    if not SELENIUM_AVAILABLE:
        raise RuntimeError(
            "Selenium not installed. Run: pip install selenium\n"
            "Also install ChromeDriver: https://chromedriver.chromium.org/"
        )

    options = Options()
    if headless:
        options.add_argument("--headless=new")
    options.add_argument("--no-sandbox")
    options.add_argument("--disable-dev-shm-usage")
    options.add_argument("--disable-gpu")
    options.add_argument("--window-size=1440,900")
    options.add_argument("--disable-extensions")
    options.add_argument("--disable-blink-features=AutomationControlled")
    options.add_experimental_option("excludeSwitches", ["enable-automation"])
    options.add_experimental_option("useAutomationExtension", False)
    options.add_argument(
        "--user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36"
    )

    if chromedriver_path:
        service = Service(chromedriver_path)
        driver = webdriver.Chrome(service=service, options=options)
    else:
        # Try auto-detect; user may have chromedriver on PATH
        driver = webdriver.Chrome(options=options)

    driver.set_page_load_timeout(30)
    return driver


# ── JavaScript helpers injected into the page ─────────────────────────────────

_JS_GET_LOGIN_CONTAINERS = """
(function() {
    const results = [];
    const viewportWidth = window.innerWidth;

    // Find login containers via password fields OR login-related forms
    let passwordInputs = Array.from(document.querySelectorAll('input[type="password"]'));

    // Fallback: if no password fields visible yet, look for login-related forms
    if (passwordInputs.length === 0) {
        const allForms = document.querySelectorAll('form');
        allForms.forEach(function(f) {
            const txt = (f.id + f.className + f.innerHTML).toLowerCase();
            if (/login|signin|sign.in|auth|account/.test(txt)) {
                const fakeInput = f.querySelector('input[type="text"], input[type="email"], input');
                if (fakeInput) passwordInputs.push(fakeInput);
            }
        });
    }

    // Also check for any text/email inputs inside obvious login containers
    if (passwordInputs.length === 0) {
        document.querySelectorAll('input[type="text"], input[type="email"]').forEach(function(inp) {
            const parent = inp.closest('form') || inp.parentElement;
            if (!parent) return;
            const txt = (parent.id + ' ' + parent.className).toLowerCase();
            if (/login|signin|auth|account|user|email/.test(txt)) {
                passwordInputs.push(inp);
            }
        });
    }

    const seen = new WeakSet();

    passwordInputs.forEach(function(input) {
        // Find best container: form > section > div
        let container = input.closest('form') ||
                        input.closest('section') ||
                        input.closest('main') ||
                        input.closest('article') ||
                        input.parentElement;

        // Walk up a bit more if container is tiny
        let el = container;
        for (let i = 0; i < 4 && el; i++) {
            const r = el.getBoundingClientRect();
            if (r.width > 100 && r.height > 60) { container = el; break; }
            el = el.parentElement;
        }

        if (!container || seen.has(container)) return;
        seen.add(container);

        const rect = container.getBoundingClientRect();
        const style = window.getComputedStyle(container);

        // Compute margins from DOM geometry
        const leftMargin  = rect.left;
        const rightMargin = viewportWidth - rect.right;

        // Child element alignment
        const children = container.querySelectorAll('input, button, a, label');
        let misalignedCount = 0;
        children.forEach(function(child) {
            const cr = child.getBoundingClientRect();
            if (cr.width === 0 || cr.height === 0) return;
            const cLeft  = cr.left  - rect.left;
            const cRight = rect.right - cr.right;
            if (cRight === 0) return;
            const cRatio = cLeft / cRight;
            const dev = Math.abs(cRatio - 1.0) * 100;
            if (dev > 8) misalignedCount++;
        });
        const childMisalignPct = children.length > 0
            ? (misalignedCount / children.length) * 100
            : 0;

        results.push({
            tag:             container.tagName,
            id:              container.id || '',
            classes:         container.className || '',
            x:               rect.left,
            y:               rect.top,
            width:           rect.width,
            height:          rect.height,
            viewportWidth:   viewportWidth,
            leftMargin:      leftMargin,
            rightMargin:     rightMargin,
            cssMarginLeft:   parseFloat(style.marginLeft)  || 0,
            cssMarginRight:  parseFloat(style.marginRight) || 0,
            cssPaddingLeft:  parseFloat(style.paddingLeft) || 0,
            cssPaddingRight: parseFloat(style.paddingRight)|| 0,
            childMisalignPct: childMisalignPct,
        });
    });

    return JSON.stringify(results);
})();
"""

_JS_PAGE_META = """
(function() {
    return JSON.stringify({
        title:   document.title,
        favicon: !!document.querySelector('link[rel*="icon"]'),
    });
})();
"""


# ── CSS Analysis via BeautifulSoup ────────────────────────────────────────────

class CSSAnalyzer:
    """
    Parses inline <style> blocks and style="" attributes from the page HTML
    to extract margin/padding rules for login-related selectors.
    """

    LOGIN_SELECTORS = re.compile(
        r'(login|signin|sign-in|log-in|auth|account|form|container|wrapper)',
        re.IGNORECASE
    )
    MARGIN_RULE = re.compile(
        r'margin(?:-left|-right)?\s*:\s*([^;]+)', re.IGNORECASE
    )
    PADDING_RULE = re.compile(
        r'padding(?:-left|-right)?\s*:\s*([^;]+)', re.IGNORECASE
    )

    def __init__(self, html: str):
        self.soup = BeautifulSoup(html, "html.parser")

    def _parse_px(self, value: str) -> Optional[float]:
        """Convert CSS value string to float pixels (best-effort)."""
        value = value.strip()
        if value.endswith("px"):
            try:
                return float(value[:-2])
            except ValueError:
                return None
        if value == "auto":
            return None
        try:
            return float(value)
        except ValueError:
            return None

    def extract_login_css_rules(self) -> dict:
        """
        Returns dict of selector → {margin_left, margin_right, padding_left, padding_right}
        for selectors that look login-related.
        """
        rules = {}

        # Inline <style> blocks
        for style_tag in self.soup.find_all("style"):
            css_text = style_tag.get_text()
            # Rough CSS rule tokenizer
            for block in re.finditer(r'([^{]+)\{([^}]+)\}', css_text):
                selector = block.group(1).strip()
                declarations = block.group(2)
                if not self.LOGIN_SELECTORS.search(selector):
                    continue
                parsed = self._parse_declarations(declarations)
                if parsed:
                    rules[selector] = parsed

        return rules

    def _parse_declarations(self, declarations: str) -> dict:
        result = {}
        for decl in declarations.split(";"):
            decl = decl.strip()
            if not decl:
                continue
            if ":" not in decl:
                continue
            prop, _, val = decl.partition(":")
            prop = prop.strip().lower()
            val  = val.strip()
            if prop == "margin":
                parts = val.split()
                if len(parts) == 4:
                    result["margin_top"]    = self._parse_px(parts[0])
                    result["margin_right"]  = self._parse_px(parts[1])
                    result["margin_bottom"] = self._parse_px(parts[2])
                    result["margin_left"]   = self._parse_px(parts[3])
                elif len(parts) == 2:
                    result["margin_top"]    = self._parse_px(parts[0])
                    result["margin_right"]  = self._parse_px(parts[1])
                    result["margin_bottom"] = self._parse_px(parts[0])
                    result["margin_left"]   = self._parse_px(parts[1])
                elif len(parts) == 1:
                    v = self._parse_px(parts[0])
                    result["margin_left"] = result["margin_right"] = v
            elif prop == "margin-left":
                result["margin_left"] = self._parse_px(val)
            elif prop == "margin-right":
                result["margin_right"] = self._parse_px(val)
            elif prop == "padding-left":
                result["padding_left"] = self._parse_px(val)
            elif prop == "padding-right":
                result["padding_right"] = self._parse_px(val)
        return result

    def count_login_forms(self) -> int:
        count = 0
        for form in self.soup.find_all("form"):
            if form.find("input", {"type": "password"}):
                count += 1
        # Also bare password inputs not in <form>
        bare = self.soup.find_all("input", {"type": "password"})
        return max(count, len(bare))

    def extract_external_css_links(self) -> list:
        return [
            link.get("href", "")
            for link in self.soup.find_all("link", rel=lambda r: r and "stylesheet" in r)
        ]


# ── Symmetry computation ──────────────────────────────────────────────────────

def compute_symmetry_ratio(left: float, right: float) -> float:
    if right == 0:
        return 0.0 if left == 0 else float("inf")
    return left / right


def compute_risk(deviation_pct: float, child_misalign_pct: float) -> tuple[str, float]:
    """Returns (risk_level, composite_score 0-100)."""
    composite = min(100.0, deviation_pct * 0.70 + child_misalign_pct * 0.30)
    if deviation_pct > 4.0:
        risk = "HIGH"
    elif deviation_pct > 2.0:
        risk = "MEDIUM"
    else:
        risk = "LOW"
    return risk, round(composite, 2)


# ── URL-level heuristics ──────────────────────────────────────────────────────

IP_PATTERN = re.compile(r'https?://\d{1,3}(\.\d{1,3}){3}')
LOGIN_URL_KW = re.compile(r'login|signin|sign-in|log-in|phish|secure|verify', re.I)


def url_heuristics(url: str) -> dict:
    return {
        "uses_https":           url.startswith("https://"),
        "login_keyword_in_url": bool(LOGIN_URL_KW.search(url)),
        "ip_address_url":       bool(IP_PATTERN.match(url)),
        "domain":               re.sub(r'https?://', '', url).split('/')[0],
    }


# ── Known legitimate domains (never flag as HIGH regardless of symmetry) ────────
TRUSTED_DOMAINS = {
    "accounts.google.com", "google.com",
    "login.microsoftonline.com", "microsoft.com", "live.com",
    "www.instagram.com", "instagram.com",
    "www.facebook.com", "facebook.com",
    "twitter.com", "x.com",
    "linkedin.com", "www.linkedin.com",
    "apple.com", "appleid.apple.com",
    "amazon.com", "www.amazon.com",
    "github.com", "www.github.com",
    "yahoo.com", "login.yahoo.com",
    "paypal.com", "www.paypal.com",
}

# ── Brand fingerprint database ───────────────────────────────────────────────
# Maps brand keywords → official login URL to compare against
BRAND_FINGERPRINTS = {
    "google":       "https://accounts.google.com/signin",
    "gmail":        "https://accounts.google.com/signin",
    "paypal":       "https://www.paypal.com/signin",
    "facebook":     "https://www.facebook.com/login",
    "instagram":    "https://www.instagram.com/accounts/login",
    "twitter":      "https://twitter.com/login",
    "microsoft":    "https://login.microsoftonline.com",
    "outlook":      "https://login.microsoftonline.com",
    "hotmail":      "https://login.microsoftonline.com",
    "apple":        "https://appleid.apple.com",
    "amazon":       "https://www.amazon.com/ap/signin",
    "netflix":      "https://www.netflix.com/login",
    "github":       "https://github.com/login",
    "linkedin":     "https://www.linkedin.com/login",
    "yahoo":        "https://login.yahoo.com",
    "dropbox":      "https://www.dropbox.com/login",
    "twitter":      "https://twitter.com/i/flow/login",
    "x.com":        "https://twitter.com/i/flow/login",
    "chase":        "https://secure.chase.com/web/auth/dashboard",
    "bank":         None,  # Too generic, skip
}

def detect_brand(title: str, url: str, page_html: str, domain: str = "") -> tuple:
    """
    Returns (brand_name, official_login_url) or (None, None) if not detected.
    Priority: 1) exact domain match  2) title/URL keywords  3) page HTML
    """
    domain_clean = domain.lower().replace("www.", "")
    title_lower  = title.lower()
    url_lower    = url.lower()
    html_snippet = page_html[:5000].lower()

    for brand, official_url in BRAND_FINGERPRINTS.items():
        if not official_url:
            continue

        # 1. Check if brand name appears in the domain being scanned
        #    e.g. "paypal" in "paypal-login.net" or "github.com"
        if brand in domain_clean:
            # Skip if this IS the official domain (trusted) — caller handles that
            return brand.capitalize(), official_url

        # 2. Check page title — most reliable signal after domain
        if brand in title_lower:
            return brand.capitalize(), official_url

        # 3. Check URL path
        if brand in url_lower:
            return brand.capitalize(), official_url

        # 4. Check HTML content (logo alt text, headings, meta tags)
        if brand in html_snippet:
            return brand.capitalize(), official_url

    return None, None


def compare_containers(suspicious: dict, original: dict) -> dict:
    """
    Compare symmetry metrics between suspicious and original page containers.
    Returns a comparison dict with differences and verdict.
    """
    if not suspicious or not original:
        return {}

    s_ratio = suspicious.get("symmetry_ratio", 1.0)
    o_ratio = original.get("symmetry_ratio", 1.0)
    s_dev   = suspicious.get("deviation_pct", 0.0)
    o_dev   = original.get("deviation_pct", 0.0)
    s_score = suspicious.get("composite_score", 0.0)
    o_score = original.get("composite_score", 0.0)

    ratio_diff = abs(s_ratio - o_ratio)
    dev_diff   = abs(s_dev - o_dev)
    score_diff = abs(s_score - o_score)

    # Width comparison (normalized to viewport)
    s_width_pct = (suspicious.get("width", 0) / suspicious.get("viewport_width", 1440)) * 100
    o_width_pct = (original.get("width", 0) / original.get("viewport_width", 1440)) * 100
    width_diff  = abs(s_width_pct - o_width_pct)

    # Verdict: if ratio differs by >0.1 OR dev differs by >5% → likely clone
    is_clone = ratio_diff > 0.1 or dev_diff > 5.0 or width_diff > 10.0

    return {
        "suspicious_ratio":   round(s_ratio, 4),
        "original_ratio":     round(o_ratio, 4),
        "ratio_diff":         round(ratio_diff, 4),
        "suspicious_dev":     round(s_dev, 2),
        "original_dev":       round(o_dev, 2),
        "dev_diff":           round(dev_diff, 2),
        "suspicious_score":   round(s_score, 2),
        "original_score":     round(o_score, 2),
        "score_diff":         round(score_diff, 2),
        "suspicious_width_pct": round(s_width_pct, 1),
        "original_width_pct":   round(o_width_pct, 1),
        "width_diff":         round(width_diff, 1),
        "is_clone":           is_clone,
    }


def is_trusted_domain(domain: str) -> bool:
    domain = domain.lower().strip()
    return domain in TRUSTED_DOMAINS or any(domain.endswith('.' + d) for d in TRUSTED_DOMAINS)

def is_side_by_side_layout(left_margin: float, right_margin: float, viewport_width: float) -> bool:
    """
    Detect intentional side-by-side layout (e.g. Instagram: image on left, form on right).
    If the form occupies less than 50% of the viewport and is pushed to one side,
    it's likely a deliberate split layout, not a phishing misalignment.
    """
    form_width = viewport_width - left_margin - right_margin
    form_pct = form_width / viewport_width if viewport_width > 0 else 1
    # If form takes less than 55% of viewport width, it's likely a split layout
    return form_pct < 0.55


# ── Main SymmetryAnalyzer ─────────────────────────────────────────────────────

class SymmetryAnalyzer:
    """
    Orchestrates Selenium + BeautifulSoup to produce a full PageReport.

    Usage:
        analyzer = SymmetryAnalyzer()
        report   = analyzer.analyze("https://example.com/login")
        analyzer.quit()
    """

    def __init__(self, headless: bool = True, chromedriver_path: Optional[str] = None):
        self.driver = build_driver(headless, chromedriver_path)

    def quit(self):
        try:
            self.driver.quit()
        except Exception:
            pass

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.quit()

    def analyze(self, url: str) -> PageReport:
        heuristics = url_heuristics(url)
        report = PageReport(
            url=url,
            title="",
            timestamp=time.time(),
            has_login_form=False,
            overall_risk="NONE",
            composite_score=0.0,
            **heuristics,
        )

        try:
            self.driver.get(url)
            WebDriverWait(self.driver, 20).until(
                EC.presence_of_element_located((By.TAG_NAME, "body"))
            )
            time.sleep(4)
        except TimeoutException:
            report.error = "Page load timed out"
            return report
        except WebDriverException as e:
            report.error = f"WebDriver error: {str(e)[:120]}"
            return report

        # ── Page meta ─────────────────────────────────────────────────────────
        report.title = self.driver.title
        try:
            report.has_favicon = bool(self.driver.find_elements(By.CSS_SELECTOR, 'link[rel*="icon"]'))
        except Exception:
            pass

        # ── Find password inputs directly via Selenium ────────────────────────
        try:
            password_inputs = self.driver.find_elements(By.CSS_SELECTOR, 'input[type="password"]')
        except Exception:
            password_inputs = []

        # ── HTML → BeautifulSoup CSS analysis ────────────────────────────────
        page_html = self.driver.page_source
        css_analyzer = CSSAnalyzer(page_html)
        login_form_count = css_analyzer.count_login_forms()
        css_rules = css_analyzer.extract_login_css_rules()

        if not password_inputs and login_form_count == 0:
            report.has_login_form = False
            report.overall_risk   = "NONE"
            return report

        report.has_login_form = True

        # ── Get geometry using Selenium directly (no JS injection needed) ─────
        viewport_width = self.driver.execute_script("return window.innerWidth")
        raw_containers = []
        seen_elements = []

        for pw_input in password_inputs:
            # Walk up the DOM to find the best container element
            container = None
            for selector in ['form', 'section', 'main', 'article', 'div']:
                try:
                    candidate = pw_input.find_element(By.XPATH,
                        f"ancestor::{selector}[1]")
                    if candidate:
                        container = candidate
                        break
                except Exception:
                    continue

            if not container:
                container = pw_input

            # Skip already-seen containers
            try:
                elem_id = container.id
                if elem_id in seen_elements:
                    continue
                seen_elements.append(elem_id)
            except Exception:
                pass

            # Get bounding rect via JavaScript on this specific element
            try:
                rect = self.driver.execute_script("""
                    var r = arguments[0].getBoundingClientRect();
                    var s = window.getComputedStyle(arguments[0]);
                    return {
                        left: r.left, top: r.top,
                        width: r.width, height: r.height,
                        right: r.right,
                        cssMarginLeft:  parseFloat(s.marginLeft)  || 0,
                        cssMarginRight: parseFloat(s.marginRight) || 0,
                        cssPaddingLeft: parseFloat(s.paddingLeft) || 0,
                        cssPaddingRight:parseFloat(s.paddingRight)|| 0,
                        tag: arguments[0].tagName,
                        id:  arguments[0].id || '',
                        cls: arguments[0].className || ''
                    };
                """, container)

                if not rect or rect['width'] < 10:
                    continue

                left_margin  = rect['left']
                right_margin = viewport_width - rect['right']

                # Child misalignment using Selenium
                children = container.find_elements(By.CSS_SELECTOR, 'input, button, a, label')
                misaligned = 0
                total_children = 0
                for child in children:
                    try:
                        cr = self.driver.execute_script(
                            "var r=arguments[0].getBoundingClientRect(); return {left:r.left,right:r.right,width:r.width,height:r.height};",
                            child
                        )
                        if cr['width'] == 0 or cr['height'] == 0:
                            continue
                        total_children += 1
                        c_left  = cr['left']  - rect['left']
                        c_right = rect['right'] - cr['right']
                        if c_right == 0:
                            continue
                        c_ratio = c_left / c_right
                        if abs(c_ratio - 1.0) * 100 > 8:
                            misaligned += 1
                    except Exception:
                        continue

                child_misalign_pct = (misaligned / total_children * 100) if total_children > 0 else 0

                raw_containers.append({
                    "tag":             rect['tag'],
                    "id":              rect['id'],
                    "classes":         str(rect['cls'])[:80],
                    "x":               rect['left'],
                    "y":               rect['top'],
                    "width":           rect['width'],
                    "height":          rect['height'],
                    "viewportWidth":   viewport_width,
                    "leftMargin":      left_margin,
                    "rightMargin":     right_margin,
                    "cssMarginLeft":   rect['cssMarginLeft'],
                    "cssMarginRight":  rect['cssMarginRight'],
                    "cssPaddingLeft":  rect['cssPaddingLeft'],
                    "cssPaddingRight": rect['cssPaddingRight'],
                    "childMisalignPct": child_misalign_pct,
                })

            except Exception:
                continue

        report.has_login_form = True

        # ── Build ContainerMetrics ────────────────────────────────────────────
        container_metrics = []
        for i, raw in enumerate(raw_containers):
            lm   = raw["leftMargin"]
            rm   = raw["rightMargin"]
            ratio = compute_symmetry_ratio(lm, rm)
            dev   = abs(ratio - 1.0) * 100 if math.isfinite(ratio) else 100.0
            risk, score = compute_risk(dev, raw["childMisalignPct"])

            cm = ContainerMetrics(
                index=i,
                tag=raw["tag"].lower(),
                id=raw["id"],
                classes=raw["classes"][:80],
                x=round(raw["x"], 1),
                y=round(raw["y"], 1),
                width=round(raw["width"], 1),
                height=round(raw["height"], 1),
                viewport_width=raw["viewportWidth"],
                left_margin=round(lm, 1),
                right_margin=round(rm, 1),
                symmetry_ratio=round(ratio, 4) if math.isfinite(ratio) else 9999.0,
                deviation_pct=round(dev, 2),
                child_misalign_pct=round(raw["childMisalignPct"], 2),
                css_margin_left=raw["cssMarginLeft"],
                css_margin_right=raw["cssMarginRight"],
                css_padding_left=raw["cssPaddingLeft"],
                css_padding_right=raw["cssPaddingRight"],
                composite_score=score,
                risk_level=risk,
            )
            container_metrics.append(cm)

        report.containers = container_metrics

        # ── Overall risk: worst container ─────────────────────────────────────
        if any(c.risk_level == "HIGH" for c in container_metrics):
            report.overall_risk = "HIGH"
        elif any(c.risk_level == "MEDIUM" for c in container_metrics):
            report.overall_risk = "MEDIUM"
        else:
            report.overall_risk = "LOW"

        if container_metrics:
            report.composite_score = round(
                sum(c.composite_score for c in container_metrics) / len(container_metrics), 2
            )

        # ── Brand detection + compare with original ───────────────────────────
        # Always try to detect brand and compare, even for trusted domains
        if True:
            detected_brand, official_url = detect_brand(
                report.title, url, page_html, domain=report.domain
            )
            if detected_brand and official_url:
                report.detected_brand = detected_brand
                report.original_url   = official_url
                # Skip self-comparison if URLs are the same site
                same_site = report.domain.replace("www.","") in official_url
                try:
                    orig_report = self._scan_url(official_url)
                    report.original_title      = orig_report.title
                    report.original_containers = orig_report.containers
                    if same_site:
                        report.clone_verdict = "CLEAN"
                    elif report.containers and orig_report.containers:
                        from dataclasses import asdict as _asdict
                        s_c = _asdict(report.containers[0])
                        o_c = _asdict(orig_report.containers[0])
                        cmp = compare_containers(s_c, o_c)
                        report.comparison = cmp
                        if cmp.get("is_clone"):
                            report.overall_risk  = "HIGH"
                            report.clone_verdict = "CLONE"
                        else:
                            report.clone_verdict = "CLEAN"
                    else:
                        report.clone_verdict = "UNKNOWN"
                except Exception:
                    report.clone_verdict = "UNKNOWN"
            else:
                report.clone_verdict = "UNKNOWN"


        return report

    def _scan_url(self, url: str) -> "PageReport":
        """Scan a second URL using the same driver instance."""
        from dataclasses import asdict as _asdict
        orig = PageReport(
            url=url, title="", timestamp=time.time(),
            has_login_form=False, overall_risk="NONE", composite_score=0.0,
            **url_heuristics(url)
        )
        try:
            self.driver.get(url)
            WebDriverWait(self.driver, 20).until(
                EC.presence_of_element_located((By.TAG_NAME, "body"))
            )
            time.sleep(4)
            orig.title = self.driver.title
            viewport_width = self.driver.execute_script("return window.innerWidth")
            pw_inputs = self.driver.find_elements(By.CSS_SELECTOR, 'input[type="password"]')
            seen_elements = []
            for pw_input in pw_inputs:
                container = None
                for sel in ['form', 'section', 'main', 'div']:
                    try:
                        c = pw_input.find_element(By.XPATH, f"ancestor::{sel}[1]")
                        if c:
                            container = c
                            break
                    except Exception:
                        continue
                if not container:
                    container = pw_input
                try:
                    eid = container.id
                    if eid in seen_elements:
                        continue
                    seen_elements.append(eid)
                except Exception:
                    pass
                try:
                    rect = self.driver.execute_script("""
                        var r=arguments[0].getBoundingClientRect();
                        var s=window.getComputedStyle(arguments[0]);
                        return {left:r.left,top:r.top,width:r.width,height:r.height,right:r.right,
                                cssMarginLeft:parseFloat(s.marginLeft)||0,
                                cssMarginRight:parseFloat(s.marginRight)||0,
                                cssPaddingLeft:parseFloat(s.paddingLeft)||0,
                                cssPaddingRight:parseFloat(s.paddingRight)||0,
                                tag:arguments[0].tagName,id:arguments[0].id||'',
                                cls:arguments[0].className||''};
                    """, container)
                    if not rect or rect['width'] < 10:
                        continue
                    lm = rect['left']
                    rm = viewport_width - rect['right']
                    ratio = compute_symmetry_ratio(lm, rm)
                    dev = abs(ratio - 1.0) * 100 if math.isfinite(ratio) else 100.0
                    risk, score = compute_risk(dev, 0)
                    orig.containers.append(ContainerMetrics(
                        index=len(orig.containers), tag=rect['tag'].lower(),
                        id=rect['id'], classes=str(rect['cls'])[:80],
                        x=round(rect['left'],1), y=round(rect['top'],1),
                        width=round(rect['width'],1), height=round(rect['height'],1),
                        viewport_width=viewport_width,
                        left_margin=round(lm,1), right_margin=round(rm,1),
                        symmetry_ratio=round(ratio,4) if math.isfinite(ratio) else 9999.0,
                        deviation_pct=round(dev,2), child_misalign_pct=0,
                        css_margin_left=rect['cssMarginLeft'],
                        css_margin_right=rect['cssMarginRight'],
                        css_padding_left=rect['cssPaddingLeft'],
                        css_padding_right=rect['cssPaddingRight'],
                        composite_score=score, risk_level=risk,
                    ))
                except Exception:
                    continue
            orig.has_login_form = len(orig.containers) > 0
        except Exception:
            pass
        return orig
