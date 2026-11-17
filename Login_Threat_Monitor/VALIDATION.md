# Validation

- 14 automated Python tests passed: boundaries, time sorting, reset after success, alert re-arming, account/IP isolation, invalid input and the synthetic demo.
- Local HTTP GET and POST integration passed; the API returned the expected 4 demo alerts.
- JavaScript syntax check passed (`node --check web/app.js`).
- Browser visual/interaction testing could not run in the build environment due to Chromium process restrictions. Verify the dashboard on your computer using the acceptance checklist in README.md.
- The Windows launcher has not been executed on Windows in the build environment. It includes the Python installation path observed during setup and two command fallbacks.
