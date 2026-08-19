"""实验一入口：测量 PPKR 各阶段运行时间与通信量（对齐 PAEE）。

实现见 ``experiment.http_benchmark``::

    python -m experiment.tcp_benchmark --trials 20
    python -m experiment.tcp_benchmark --trials 20 --auto-server
    python -m experiment.tcp_benchmark --protocols oprf_ppkr encpw_plus --trials 20
"""

from experiment.http_benchmark import main

if __name__ == "__main__":
    main()
