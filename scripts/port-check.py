def max_port(protocol):
    """ 获取给定协议（tcp或udp）的最大端口号 """
    max_port_number = 0
    try:
        with open(f"/proc/net/{protocol}", "r") as file:
            next(file)  # 跳过第一行（标题行）
            for line in file:
                # 分割数据行，端口号是第二栏的一部分
                parts = line.split()
                local_address = parts[1]
                local_port_hex = local_address.split(":")[1]
                local_port = int(local_port_hex, 16)  # 16进制转为10进制
                if local_port > max_port_number:
                    max_port_number = local_port
    except FileNotFoundError:
        print(f"无法打开 /proc/net/{protocol}，请确保你正在使用 Linux 系统并且有适当的权限。")
    except Exception as e:
        print(f"发生错误: {e}")

    return max_port_number

tcp_max_port = max_port("tcp")
udp_max_port = max_port("udp")

print(f"当前使用的最大TCP端口号是: {tcp_max_port}")
print(f"当前使用的最大UDP端口号是: {udp_max_port}")