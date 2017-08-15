#! /usr/bin/env python
import sys

if sys.version_info[0] != 3:
    print("This script requires Python version >= 3")
    sys.exit(1)

import argparse
import os
import yaml
import logging
from shell import ex
import tempfile
import pexpect
import shlex
import re
from contextlib import contextmanager
from urllib.parse import urlparse
import uuid
import requests
import base64
import gzip
from datetime import datetime
import tarfile
from rotate_backups import RotateBackups, coerce_location
import multiprocessing as mp
import traceback
from functools import partial
import subprocess

def get_config(p):
    with open(p, "r") as f:
        conf = f.read()
    d = dict(yaml.load(conf))
    return d

def shjoin(s):
    return " ".join(map(shlex.quote, s))

class LFTPError(RuntimeError): pass
class AccessFailed(LFTPError): pass
class LoginFailed(LFTPError): pass
class ConnectionRefused(LFTPError): pass

class LFTP:
    prompt = [
        r"lftp.*>", 
        r": (.*(?:Access failed|Login failed):.*)\r\n",
        r"Connection refused",
        # r".*(Failed|failed).*\r\n",
        # r"[A-Za-z]+: (.*(?:error|Error|).*): (.*)\r\n",
        # r"[A-Za-z]+: (.*(?:failed|Failed).*): (.*)\r\n",
    ]
    error_re = re.compile(r".*(Access failed|Login failed): (.*)")

    def _clean(self, s):
        ansi_escape = re.compile(r'\x1b[^m]*m')
        ns = ansi_escape.sub('', s)
        return ns.strip()

    
    def __init__(self, exe, basepath = "/"):
        self.exe = exe
        self.basepath = basepath
    
    def _handle_error(self, index):
        # print("HANDLE ERROR", index)
        msg = ""
        if index == 0:
            return index, msg
        elif index == 1:
            # line = self.proc.before + " " + self.proc.after
            # print("line", line)
            match = self.proc.match.group(1).strip()
            # print("MATCH")
            # print(match)
            # print("ENDMATCH")
            # this can be multiple lines
            lines = match.split("\r")
            # line = lines[-1]
            # lines = list(filter(self.error_re.match, lines))
            lines = map(self.error_re.match, lines)
            lines = [l for l in lines if l != None]
            line = lines[-1]


            # realmatch = re.search(r".*(Access failed|Login failed): (.*)", line)
            error = line.group(1)
            info = line.group(2)

            msg = error + ": " + info


            # print("LINE")
            # print(line)
            # print("ENDLINE")

            # match = self.error_re.match(line)
            # print(match)
            # error, info = line.split(":", 1)
            # info = info.strip()
            # error = error.strip()
            # print("ERROR:", error, "INFO:", info)
            # print(error == "Access failed")
            if error == "Login failed":
                raise LoginFailed(msg)
            elif error == "Access failed":
                raise AccessFailed(msg)
            else:
                raise LFTPError(msg)

        elif index == 2:
            # print("BEFAFT", self.proc.before, self.proc.after)
            raise ConnectionRefused("Connection was refused by server")
        else:
            self.l.error(self.proc.before + " " + self.proc.after)
            raise LFTPError(self.proc.before + " " +self.proc.after)
        # return index, msg

    def connect(self, logger, host, user, pwd, port=None, init_cmds = [], verbose=False):
        self.l = logger
        cmd = [
            self.exe,
            "-u", "{}".format(user),
            host,
        ]
        
        if port != None:
            cmd.append("-p")
            cmd.append(port)

        if len(init_cmds) > 0:
            cmd.append("-e")
            cmd.append(",".join(init_cmds))

        cmds = " ".join(map(shlex.quote, cmd))
        self.l.debug(cmds)

        self.proc = pexpect.spawnu(cmds)
        if verbose:
            self.proc.logfile = sys.stdout
        try:
            self.l.debug("expecting init")
            self.proc.expect("Password:")
            self.proc.sendline(pwd)
            index = self.proc.expect(self.prompt)
            # execute ls to test
            self.proc.sendline("ls")
            index = self.proc.expect(self.prompt)
            self._handle_error(index)
        except Exception as e:
            self.l.critical("FTP connection to {}@{} could not be established".format(user, host))
            self.l.debug(str(e))
            raise

    def ls(self):
        lines = self.ex("ls")
        lines = [l.split(" ")[-1].strip() for l in lines]
        return lines[:-1]

    def exists(self, e):
        lines = self.ls()
        return e in lines

    def pwd(self):
        url = urlparse(self.ex("pwd")[0].strip())
        pwd = url.path
        if not pwd.startswith("/"):
            pwd = "/" + pwd
        return pwd


    def close(self):
        self.proc.terminate()
        del self.proc

    def ex(self, cmd, timeout=30):
        assert self.proc
        if type(cmd) == list:
            cmd = shjoin(cmd)
        self.l.debug("executing command '{}', timeout: {}s".format(cmd, timeout))
        try:
            self.proc.sendline(cmd)
            index = self.proc.expect(self.prompt, timeout=timeout)
            # print("INDEX", index)
            while index != 0:
                try:
                    self._handle_error(index)
                except AccessFailed as e:
                    self.l.warning(str(e))
                    index = self.proc.expect(self.prompt, timeout=timeout)
                    pass
            res = self.proc.before
            # res = str(self.proc.before, "utf-8")
            lines = res.split("\r\n")
            lines = list(map(self._clean, lines))
            return lines[1:]
        except pexpect.exceptions.TIMEOUT:
            self.l.critical("Timeout ({}s) when executing command '{}'".format(timeout, cmd))
            # we need to terminate, no use in continuing
            raise
        except:
            self.l.critical("Error executing command '{}'".format(cmd))
            raise

    def cd(self, d):
        self.ex(["cd", d])

    @contextmanager
    def cwd(self, d):
        pwd = self.pwd()
        try:
            self.cd(d)
            yield
        except:
            raise
        finally:
            self.cd(pwd)

    @contextmanager
    def tmpfile(self, src, dest):
        try: 
            self.put(src, dest)
            yield
        except:
            raise
        finally:
            self.rm(dest)

    @contextmanager
    def tmpfiles(self, fdict):
        try:
            for dest, src in fdict.items():
                self.put(src, dest)
            yield
        except:
            raise
        finally:
            for dest, src in fdict.items():
                try:
                    self.rm(dest)
                except:
                    self.l.warning("tmpfiles: {} could not be removed".format(dest))
                    raise

    @contextmanager
    def tmpdir(self, d):
        try:
            self.mkdir(d)
            yield
        except:
            raise
        finally:
            self.rmdir(d)

    def mkdir(self, d):
        return self.ex(["mkdir", "-p", "-f", d])
    
    def rmdir(self, d):
        return self.ex(["rmdir", d])

    def mirror(self, remote, local, reverse=False, timeout=3*60*60, parallel=1, exclude=[], delete=True):
        cmd = ["mirror", "--parallel={}".format(parallel)]
        if reverse:
            cmd.append("--reverse")

        if delete:
            cmd.append("--delete")

        for ex in exclude:
            cmd.append("--exclude")
            cmd.append(ex)

        cmd.append(remote)
        cmd.append(local)

        start = datetime.now()
        result = self.ex(cmd, timeout = timeout)
        delta = datetime.now() - start
        self.l.debug("mirror ran for {} seconds".format(delta.seconds))

        return result

    def put(self, src, dest=None):
        f = None
        if not os.path.isfile(src):
            f = tempfile.NamedTemporaryFile()
            f.write(src.encode())
            f.flush()
            srcf = f.name
        else:
            srcf = src
        
        cmd = ["put", srcf]
        if dest != None:
            cmd.extend(["-o", dest])

        self.l.debug("put {} -> {}".format(srcf, dest if dest else os.path.basename(srcf)))
        res = self.ex(cmd)

        if f: f.close()

        return res

    def rm(self, f):
        try:
            return self.ex(["rm", "-f", f])
        except:
            self.l.warning("removal of file {} unsuccessful".format(f))
            pass


def check_requirements(l):
    l.debug("checking if lftp is installed")
    which_lftp = ex("which lftp")
    if which_lftp.re() != 0:
        l.debug(which_lftp.stdout())
        raise RuntimeError("lftp was not found")
    lftp_path = str(which_lftp.stdout(), "utf-8").strip()

    return LFTP(exe=lftp_path)


MYSQL_CONFIG_REDAXO = """
    // extract db config
    $config_loc = '../redaxo/include/master.inc.php';
    $config_str = file_get_contents($config_loc) ;
    $config_str = substr($config_str, strpos($config_str, '// ----------------- DB1')+strlen('// ----------------- DB1')) ;
    $config_str = substr($config_str, 0, strpos($config_str, '// ----------------- DB2 - if necessary')) ;
    $REX = array('DB' => array('1')) ;

    eval($config_str) ;
    $config_rex = $REX['DB']['1'] ;
    $config = array(
        "host" => $config_rex["HOST"],
        "name" => $config_rex["NAME"],
        "user" => $config_rex["LOGIN"],
        "pass" => $config_rex["PSW"]
    );
"""

MYSQL_CONFIG_EXPLICIT = """
    $config = array(
        "host" => "{host}",
        "name" => "{name}",
        "user" => "{user}",
        "pass" => "{passw}",
    );
"""

MYSQL_CONFIG_WORDPRESS = """
    include "../wp-config.php";

    $config = array(
        "host" => DB_HOST,
        "name" => DB_NAME,
        "user" => DB_USER,
        "pass" => DB_PASSWORD,
    );


"""


MYSQL_DUMP_TEMPLATE = """<?php

include 'vendor/autoload.php';
use Ifsnop\Mysqldump as IMysqldump;

try {{
    {mysql_config}
    $dump = new IMysqldump\Mysqldump('mysql:host='.$config["host"].';dbname='.$config["name"].'', $config["user"], $config["pass"]);
    ob_start();
    $dump->start('php://output');
    $dumps = ob_get_clean();
    ob_end_clean();
    header("HTTP/1.1 200");
    header('Content-Type: charset=utf-8');
    echo $dumps;
}} catch (\Exception $e) {{
    header("HTTP/1.1 500");
    echo 'mysqldump-php error: ' . $e->getMessage();
}}

// this script runs exactly ONCE
unlink(__FILE__);




"""

def get_mysql_dump(l, args, task, conn):
    l.info("getting mysql dump")

    docroot = task["remote_docroot"]

    mysqlfilename = str(uuid.uuid4())+".php"
    dumpurl = "{}/mysqldump/{}".format(task["public_url"], mysqlfilename)
    
    if task["mysql_config"] == "redaxo":
        l.debug("using conf mode redaxo")
        mysql_config = MYSQL_CONFIG_REDAXO
    elif type(task["mysql_config"]) == dict:
        l.debug("using conf mode explicit")
        conf = task["mysql_config"]
        mysql_config = MYSQL_CONFIG_EXPLICIT.format(
            host=conf["host"],
            name=conf["name"],
            user=conf["user"],
            passw=conf["pass"],
        )
    elif task["mysql_config"] == "wordpress":
        l.debug("using conf mode wordpress")
        mysql_config = MYSQL_CONFIG_WORDPRESS
    else:
        raise ValueError("Invalid MySQL config mode: {}".format(task["mysql_config"]))
    
    mysqldumpscript = MYSQL_DUMP_TEMPLATE.format(
            mysql_config = mysql_config,
            )

    # print(mysqldumpscript)
    
    with conn.cwd(docroot):
        conn.mkdir("mysqldump")
    with conn.cwd(os.path.join(docroot, "mysqldump")):
        if not conn.exists("vendor") or args.force_vendor:
            l.debug("uploading required files")
            conn.mirror("./vendor", "vendor", parallel=int(task["max_conn"]), reverse=True, delete=False)
        with conn.tmpfile(mysqldumpscript, mysqlfilename):
            l.debug("requesting dump from {}".format(dumpurl))
            r = requests.get(dumpurl)

    if r.status_code != 200:
        l.error("failed to get dump, server responded with {}".format(r.status_code))
        l.debug(r.content[:2000])
        raise RuntimeError("Unable to obtain mysql dump")
    else:
        try:
            # print("get text from res")
            # print(r.content)
            # plain = r.text
            # plain = str(r.content, "utf-8")
            plain = r.content
            # print(plain[:200])
        except:
            l.error("Error decrypting. response was: " + r.content[:2000])
            raise
        l.info("dump obtained")
        return plain

class LoggerAdapter(logging.LoggerAdapter):
    def __init__(self, l, name):
        super().__init__(l, {})
        self.name = name.upper()

    def process(self, msg, kwargs):
        return "" + self.name + " - " + msg, kwargs

def handle_task(task, args, config):
    # l = make_logger(args)
    # l = logging.getLogger(task["name"])
    ll = make_logger(args, "shbackup - " + task["name"].upper())
    start = datetime.now()
    conn = check_requirements(ll)


    # ll = LoggerAdapter(l, task["name"])
    try:

        auth = task["auth"]
        ll.info("{} start".format(task["name"]))

        init_cmds = task["ftp_init_cmds"] if "ftp_init_cmds" in task and type(task["ftp_init_cmds"]) == list else []

        conn.connect(
            ll, 
            host = auth["host"], 
            user = auth["user"], 
            pwd = auth["pass"], 
            port = auth["port"] if "port" in auth else None,
            init_cmds = init_cmds,
            verbose = args.verbose
        )

        local_dir = task["local_dir"]
        remote_dir = task["remote_dir"]
        sql_dir = os.path.join(local_dir, "db")
        files_dir = os.path.join(local_dir, "files")
        current_dir = os.path.join(files_dir, "current")
        versions_dir = os.path.join(files_dir, "versions")

        do_database = not args.no_db and ("mysql_config" in task and task["mysql_config"] != False)
        do_files = not args.no_files and ("sync_files" in task and task["sync_files"] != False)

        # print(task["name"], do_database, do_files)
        # return True

        for d in [sql_dir, current_dir, versions_dir]:
            os.system("mkdir -p {}".format(d))

        if do_database:
            dump = get_mysql_dump(ll, args, task, conn)
            mysql_dump_filename = os.path.join(sql_dir, "{}_mysql_{}.sql.gz".format(task["name"], datetime.now().strftime("%Y-%m-%d-%H-%M-%S")))
            with gzip.open(mysql_dump_filename, "wb",) as f:
                ll.debug("writing to {}".format(mysql_dump_filename))
                f.write(dump)


        if do_files:
            ll.info("Syncing remote directory to current cache")
            exs = task["excludes"] if type(task["excludes"]) == list else []
            exs.append("mysqldump/")
            with conn.cwd(remote_dir):
                conn.mirror("./", current_dir, parallel=int(task["max_conn"]), exclude=exs)

            files_version_filename = os.path.join(versions_dir, "{}_files_{}.tar.gz".format(task["name"], datetime.now().strftime("%Y-%m-%d-%H-%M-%S")))
            ll.info("Building tarball archive")
            with tarfile.open(files_version_filename, "w:gz") as tar:
                ll.debug("writing to {}".format(files_version_filename))
                tar.add(current_dir, arcname=os.path.basename(current_dir))
        
        # if do_database:
        ll.info("Rotating database versions")
        # db_retention = config["default_db_retention"] if "default_db_retention" in config else {}
        # db_retention.update(task["db_retention"] if "db_retention" in task else {})
        if "db_retention" in task:
            db_retention = task["db_retention"]
        else:
            db_retention = config["default_db_retention"]
        ll.debug("db retention: "+repr(db_retention))
        db_rotator = RotateBackups(db_retention, dry_run=False, prefer_recent=True, strict=False)
        dbloc = coerce_location(sql_dir)
        db_rotator.rotate_backups(dbloc)
        
        # if do_files:
        ll.info("Rotating files versions")
        # files_retention = config["default_files_retention"] if "default_files_retention" in config else {}
        # files_retention.update(task["files_retention"] if "files_retention" in task else {})
        if "files_retention" in task:
            files_retention = task["files_retention"]
        else:
            files_retention = config["default_files_retention"]
        ll.debug("files retention: "+repr(files_retention))
        files_rotator = RotateBackups(files_retention, dry_run=False, prefer_recent=True, strict=False)
        filesloc = coerce_location(versions_dir)
        files_rotator.rotate_backups(filesloc)

        conn.close()

        if "post_cmd" in task and task["post_cmd"] and not args.skip_post_cmds:
            try:
                cmd = task["post_cmd"]
                ll.info("Executing post command")
                ll.debug(cmd)
                with open(os.devnull, 'w') as FNULL:
                    subprocess.check_call(cmd, shell=True, stdout=FNULL, stderr=subprocess.STDOUT)
            except:
                ll.error("Error when executing post command")


        delta = datetime.now() - start
        ll.info("{} completed in {}s".format(task["name"], delta.seconds))
        
        return True
    except KeyboardInterrupt:
        print("KeyboardInterrupt caught while processing task {}".format(task["name"]))
        sys.exit(0)
        return False
    except pexpect.exceptions.TIMEOUT:
        ll.error("Timeout caught")
        return False
    except Exception as e:
        ll.critical("Error while processing {}. continuing".format(task["name"]))
        ll.critical(str(e))
        if ll.getEffectiveLevel() <= logging.DEBUG:
            traceback.print_exc()
        return False

def make_logger(args, name = "shbackup"):
    l = logging.getLogger(name)
    ch = logging.StreamHandler()
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    ch.setFormatter(formatter)
    l.addHandler(ch)

    # fh = logging.FileHandler(logfile, encoding="utf-8")
    # fh.setFormatter(formatter)
    # l.addHandler(fh)
    
    for o in l, ch: o.setLevel(logging.INFO)

    if args.debug:
        for o in l, ch: o.setLevel(logging.DEBUG)
        # ch.setLevel(logging.DEBUG)
        # l.setLevel(logging.DEBUG)
    if args.quiet:
        for o in l, ch: o.setLevel(logging.WARNING)
        # ch.setLevel(logging.WARNING)
        # l.setLevel(logging.WARNING)

    return l

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--config-file", "-c", default=os.path.expanduser("~/.shbackup"))
    p.add_argument("--force-vendor", action="store_true")
    p.add_argument("--debug", action="store_true")
    p.add_argument("--quiet", action="store_true")
    p.add_argument("--verbose", action="store_true")
    p.add_argument("--no-files", action="store_true")
    p.add_argument("--no-db", action="store_true")
    p.add_argument("--skip-post-cmds", action="store_true")
    p.add_argument("--only", nargs='+')
    p.add_argument("--exclude", nargs='+', default=[])

    args = p.parse_args()
    

    try:
        start = datetime.now()
        config = get_config(args.config_file)
        l = make_logger(args)#, config["logfile"])

        # filter tasks
        tasks = [t for t in config["tasks"] if (not args.only or t["name"] in args.only) and t["name"] not in args.exclude]
        task_names = [t["name"] for t in tasks]
        # print(task_names)
        # return

        l.info("Begin run, executing tasks {}".format(", ".join(task_names)))

        if config["process_count"] == 1 or len(tasks) == 1:
            # for task in config["tasks"]:
                # handle_task(task, args, config)
            results = map(partial(handle_task, args=args, config=config), tasks)
        else:
            # launch a pool
            nproc = min(config["process_count"], len(tasks))
            l.debug("Launching process pool with {} processes".format(nproc))
            p = mp.Pool(nproc)
            try:
                # mp.log_to_stderr().setLevel(logging.DEBUG)
                results = p.map(partial(handle_task, args=args, config=config), tasks)
                p.close()
                p.join()
            except KeyboardInterrupt:
                print("KeyboardInterrupt")
                p.terminate()
                sys.exit(0)
            
        delta = datetime.now() - start
        l.info("Run completed in {}s".format(delta.seconds))
        if not all(results):
            l.error("There were errors for some tasks")
            for t, r in zip(config["tasks"], results):
                if not r:
                    l.error("Task {} failed".format(t["name"]))

    except Exception as e:
        l.critical(str(e))
        if l.getEffectiveLevel() <= logging.DEBUG:
            # raise e
            traceback.print_exc()
            sys.exit(1)



if "__main__" == __name__:
    main()
