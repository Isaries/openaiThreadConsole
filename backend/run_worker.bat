@echo off
echo Starting Huey Worker...
set PYTHONPATH=.
python -m huey.bin.huey_consumer huey_worker.huey -w 2 -v
pause
