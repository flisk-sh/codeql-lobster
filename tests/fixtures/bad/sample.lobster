def main():
    launch_subprocess(["sh", "-c", "make " + target])
    launch_subprocess(["git", "clone", url + "/repo"])
    read_file("/etc/passwd")
    write_file("../outside.txt", "x")
    api_token = "abc123"
