@echo off
echo.
echo  Installing dependencies...
pip install flask selenium beautifulsoup4 reportlab
echo.
echo  Starting PhishGuard AI...
echo  Open http://localhost:5000 in your browser
echo.
python app.py
pause
