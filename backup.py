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
from Crypto.Cipher import AES
from Crypto import Random
import gzip
from datetime import datetime
import tarfile
from rotate_backups import RotateBackups, coerce_location

def get_config(l, p):
    l.debug(p)
    with open(p, "r") as f:
        conf = f.read()
    d = yaml.load(conf)
    return d

def shjoin(s):
    return " ".join(map(shlex.quote, s))

class LFTP:
    prompt = r"lftp.*>"

    def _clean(self, s):
        ansi_escape = re.compile(r'\x1b[^m]*m')
        ns = ansi_escape.sub('', s)
        return ns.strip()

    
    def __init__(self, exe, basepath = "/"):
        self.exe = exe
        self.basepath = basepath

    def connect(self, logger, host, user, pwd, port=None):
        self.l = logger
        cmd = [
            self.exe,
            "-u", "{}".format(user),
            host,
        ]
        
        if port != None:
            cmd.append("-p")
            cmd.append(port)

        cmds = " ".join(map(shlex.quote, cmd))
        self.l.debug(cmds)

        try:
            self.l.debug("expecting init")
            self.proc.expect("Password:")
            self.proc.sendline(pwd)
            self.proc.expect(self.prompt)
        except:
            self.l.critical("FTP connection to {}@{} could not be established".format(user, host))
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
            self.proc.expect(self.prompt, timeout=timeout)
            res = str(self.proc.before, "utf-8")
            lines = res.split("\r\n")
            lines = list(map(self._clean, lines))
            return lines[1:]
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
        finally:
            self.cd(pwd)

    @contextmanager
    def tmpfile(self, src, dest):
        try: 
            self.put(src, dest)
            yield
        finally:
            self.rm(dest)

    @contextmanager
    def tmpfiles(self, fdict):
        try:
            for dest, src in fdict.items():
                self.put(src, dest)
            yield
        finally:
            for dest, src in fdict.items():
                try:
                    self.rm(dest)
                except:
                    self.l.warning("tmpfiles: {} could not be removed".format(dest))

    @contextmanager
    def tmpdir(self, d):
        try:
            self.mkdir(d)
            yield
        finally:
            self.rmdir(d)

    def mkdir(self, d):
        return self.ex(["mkdir", "-p", d])
    
    def rmdir(self, d):
        return self.ex(["rmdir", d])

    def mirror(self, remote, local, reverse=False, timeout=30*60, parallel=1, exclude=[]):
        cmd = ["mirror", "--parallel={}".format(parallel)]
        if reverse != False:
            cmd.append("--reverse")

        for ex in exclude:
            cmd.append("--exclude")
            cmd.append(ex)

        cmd.append(remote)
        cmd.append(local)
        return self.ex(cmd, timeout = timeout)

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
        return self.ex(["rm", f])


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
    include "wp-config.php";

    $config = array(
        "host" => DB_HOST
        "name" => DB_NAME,
        "user" => DB_USER,
        "pass" => DB_PASSWORD,
    );

"""


MYSQL_DUMP_TEMPLATE = """<?php

include 'vendor/autoload.php';
use Ifsnop\Mysqldump as IMysqldump;

$aes_key = base64_decode('{aes_key}');
$aes_iv = base64_decode('{aes_iv}');

$aes = new \phpseclib\Crypt\AES(CRYPT_AES_MODE_CBC);
$aes->setKey($aes_key);
$aes->setIV($aes_iv);

try {{
    {mysql_config}
    $dump = new IMysqldump\Mysqldump('mysql:host='.$config["host"].';dbname='.$config["name"].'', $config["user"], $config["pass"]);
    ob_start();
    $dump->start('php://output');
    $dumps = ob_get_clean();
    ob_end_clean();
    $cipher = $aes->encrypt($dumps);
    header("HTTP/1.1 200");
    echo $cipher;
}} catch (\Exception $e) {{
    header("HTTP/1.1 500");
    echo 'mysqldump-php error: ' . $e->getMessage();
}}




"""

def get_mysql_dump(l, args, task, conn, aes_key, aes_iv, aes):
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
            aes_key=str(base64.b64encode(aes_key), "utf-8"),
            aes_iv=str(base64.b64encode(aes_iv), "utf-8"),
            mysql_config = mysql_config,
            )

    conn.mkdir("mysqldump")
    with conn.cwd(docroot+"/mysqldump"):
        if not conn.exists("vendor") or args.force_vendor:
            conn.mirror("./vendor", "vendor", reverse=True)
        with conn.tmpfile(mysqldumpscript, mysqlfilename):
            r = requests.get(dumpurl)

    if r.status_code != 200:
        l.error("failed to get dump, server responded with {}".format(r.status_code))
        l.debug(r.text)
        raise RuntimeError("Unable to obtain mysql dump")
    else:
        try:
            plain = aes.decrypt(r.content)
            plain = str(plain, "utf-8").strip()
        except:
            ll.error("Error decrypting. response was: " + r.text)
        l.info("dump obtained")
        return plain

class LoggerAdapter(logging.LoggerAdapter):
    def __init__(self, l, name):
        super().__init__(l, {})
        self.name = name.upper()

    def process(self, msg, kwargs):
        return "" + self.name + " - " + msg, kwargs


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--config-file", "-c", default=os.path.expanduser("~/.shbackup"))
    p.add_argument("--force-vendor", action="store_true")
    p.add_argument("--debug", action="store_true")
    p.add_argument("--quiet", action="store_true")

    args = p.parse_args()

    l = logging.getLogger("shbackup")
    ch = logging.StreamHandler()
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    ch.setFormatter(formatter)
    l.addHandler(ch)
    
    if args.debug:
        ch.setLevel(logging.DEBUG)
        l.setLevel(logging.DEBUG)
    else:
        ch.setLevel(logging.INFO)
        l.setLevel(logging.INFO)

    try:
        config = get_config(l, args.config_file)
        conn = check_requirements(l)

        l.info("Generating temporary AES keys for this run")
        aes_key = os.urandom(16)
        aes_iv = os.urandom(16)
        aes = AES.new(aes_key, AES.MODE_CBC, aes_iv)

        for task in config["tasks"]:
            ll = LoggerAdapter(l, task["name"])
            try:

                auth = task["auth"]
                ll.info(task["name"])
                conn.connect(ll, host = auth["host"], user = auth["user"], pwd = auth["pass"], port = auth["port"] if "port" in auth else None)

                local_dir = task["local_dir"]
                remote_dir = task["remote_dir"]
                sql_dir = os.path.join(local_dir, "db")
                files_dir = os.path.join(local_dir, "files")
                current_dir = os.path.join(files_dir, "current")
                versions_dir = os.path.join(files_dir, "versions")

                for d in [sql_dir, current_dir, versions_dir]:
                    os.system("mkdir -p {}".format(d))

                dump = get_mysql_dump(ll, args, task, conn, aes_key, aes_iv, aes)
                mysql_dump_filename = os.path.join(sql_dir, "{}_mysql_{}.sql.gz".format(task["name"], datetime.now().strftime("%Y-%m-%d-%H-%M-%S")))
                with gzip.open(mysql_dump_filename, "wt") as f:
                    ll.debug("writing to {}".format(mysql_dump_filename))
                    f.write(dump)


                ll.info("Syncing remote directory to current cache")
                exs = task["excludes"] if type(task["excludes"]) == list else []
                exs.append("mysqldump/")
                with conn.cwd(remote_dir):
                    conn.mirror("./", current_dir, parallel=int(task["max_conn"]), exclude=exs)

                files_version_filename = os.path.join(versions_dir, "{}_files_{}.tar.gz".format(task["name"], datetime.now().strftime("%Y-%m-%d-%H-%M-%S")))
                with tarfile.open(files_version_filename, "w:gz") as tar:
                    ll.debug("writing to {}".format(files_version_filename))
                    tar.add(current_dir, arcname=os.path.basename(current_dir))
                
                ll.info("rotating backups")
                db_retention = config["default_db_retention"] if "default_db_retention" in config else {}
                db_retention.update(task["db_retention"] if "db_retention" in task else {})
                ll.debug("db retention: "+repr(db_retention))
                db_rotator = RotateBackups(db_retention, dry_run=False)
                dbloc = coerce_location(sql_dir)
                db_rotator.rotate_backups(dbloc)
                
                files_retention = config["default_files_retention"] if "default_files_retention" in config else {}
                files_retention.update(task["files_retention"] if "files_retention" in task else {})
                ll.debug("files retention: "+repr(files_retention))
                files_rotator = RotateBackups(files_retention, dry_run=False)
                filesloc = coerce_location(sql_dir)
                files_rotator.rotate_backups(filesloc)




                conn.close()
            except:
                ll.error("Error while processing {}. continuing".format(task["name"]))
                if ll.getEffectiveLevel() <= logging.DEBUG:
                    raise
            
        l.info("Run completed")

    except Exception as e:
        l.critical(str(e))
        if l.getEffectiveLevel() <= logging.DEBUG:
            raise e



if "__main__" == __name__:
    main()
