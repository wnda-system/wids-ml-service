# Model C service

API: `model_c_training_plan_v2.md` section 6 · model: `../model/` · test vectors: `../test_vectors/`

| file | |
|---|---|
| `model_c_service.py` | the service (Python standard library HTTP server + the model venv) |
| `model_c.token` | bearer token, chmod 600 — **do not copy into git/reports**; give to the sensor out of band |
| `model_c.service` | systemd `--user` unit (not installed — see report.md "Service") |
| `check_service.py` | contract checks + test vectors; `--record` rewrites `response_*.json` |

Run in the foreground (for testing):

    cd ~/experiment_1/model_c/service
    OMP_NUM_THREADS=2 ~/experiment_1/.venv/bin/python model_c_service.py --host 127.0.0.1 --port 8500

Check (token read from file, never printed):

    ~/experiment_1/.venv/bin/python check_service.py --url http://127.0.0.1:8500

As a user service (after the cluster admins approve, see report.md):

    systemctl --user start|stop|restart|status model_c.service
    journalctl --user -u model_c.service -f
