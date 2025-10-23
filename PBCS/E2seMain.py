import sys
import configparser
import Constants
from Client import Client
from AuthServer import AuthServer

def main():
    if len(sys.argv) == 1:
        print("第一个参数：client/authserver")
        print("如果第一个参数是 client，第二个参数是源文件路径")
        return

    role = sys.argv[1]
    print(role)


    if role == Constants.CLIENT:
        if len(sys.argv) < 3:
            print("请在 args[1] 中指定源文件路径")
            return

        source_file_path = sys.argv[2]

        print("客户端测试整个流程")
        print(f"源文件路径为：{source_file_path}")
        print("耗时统计 (ms)")
        print("ibOPRF, give, ibOPRF, take, plainDep, plainRet, secureDepOpt, secureRetOpt, secureDep, secureRet, enc, dec, partNum")

        # 从 config.properties 加载 AWS 和 S3 配置
        config = configparser.ConfigParser()
        config.read("config.properties")

        access_key_id = config.get("DEFAULT", "accessKeyId", fallback=None)
        secret_key_id = config.get("DEFAULT", "secretKeyId", fallback=None)
        region_name = config.get("DEFAULT", "regionName", fallback=None)
        bucket_name = config.get("DEFAULT", "bucketName", fallback=None)
        print(f"authserverName: {Constants.AUTH_SERVER_NAME}")
        # 初始化时间指标累加器
        metrics = {
            "oprf_time": 0,
            "register_time": 0,
            "oprf_time1": 0,
            "give_time": 0,
            "oprf_time2": 0,
            "take_time": 0,
            "dep_plain_time": 0,
            "ret_plain_time": 0,
            "dep_enc_time_multi": 0,
            "ret_dec_time_multi": 0,
            "dep_enc_time_one": 0,
            "ret_dec_time_one": 0,
            "enc_time": 0,
            "dec_time": 0,
            "part_num": 0,
            "total_commucation_scale": 0
        }
        print("bucket_name", bucket_name)
        print("region_name", region_name)

        for j in range(10):

            print(f"\n=========== 第 {j + 1} 次测试 ===========")

            client = Client(access_key_id, secret_key_id, region_name, bucket_name)
            (oprf_time, register_time, oprf_time1, give_time, oprf_time2, take_time,
             dep_plain_time, ret_plain_time,
             dep_enc_time_multi, ret_dec_time_multi,
             dep_enc_time_one, ret_dec_time_one,
             enc_time, dec_time, part_num,total_commucation_scale)=client.start(source_file_path)
            # client.start_rgt()

            # 累加每次的时间
            metrics["oprf_time"] += oprf_time
            metrics["register_time"] += register_time
            metrics["oprf_time1"] += oprf_time1
            metrics["give_time"] += give_time
            metrics["oprf_time2"] += oprf_time2
            metrics["take_time"] += take_time
            metrics["dep_plain_time"] += dep_plain_time
            metrics["ret_plain_time"] += ret_plain_time
            metrics["dep_enc_time_multi"] += dep_enc_time_multi
            metrics["ret_dec_time_multi"] += ret_dec_time_multi
            metrics["dep_enc_time_one"] += dep_enc_time_one
            metrics["ret_dec_time_one"] += ret_dec_time_one
            metrics["enc_time"] += enc_time
            metrics["dec_time"] += dec_time
            metrics["part_num"] += part_num
            metrics["total_commucation_scale"] += total_commucation_scale

            # 计算平均值
        print("\n========== 平均时间指标（10次） ==========")
        for k, v in metrics.items():
            print(f"{k}: {v / 10:.2f} ms" if "time" in k else f"{k}: {v / 10:.2f}")

    elif role == Constants.AUTH_SERVER:
        print("运行 AuthServer")
        server = AuthServer()
        server.start()

    else:
        print("参数错误，应为 client + 文件路径 或 authserver")

if __name__ == "__main__":
    main()
