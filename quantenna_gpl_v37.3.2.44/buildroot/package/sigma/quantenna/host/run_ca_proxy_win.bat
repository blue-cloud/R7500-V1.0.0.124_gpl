@echo "Feel free update this batch file with actual CA & Server IP:port and path to python."
@echo "run sigma proxy server."
:start
c:\Python27\python.exe sigma_ca_proxy.py --server-ip=127.0.0.1 --server-port=10000 --ca-ip=127.0.0.1 --ca-port=9080
goto start
