"""Isolated synthetic HTTP transport lab. Never a production adapter."""
from __future__ import annotations

import hashlib
from http.client import HTTPConnection
import json
import os
import subprocess
import sys
import threading
import time
import uuid
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from akdbx import admission


class Lab:
    def __init__(self, target, snapshots, staging, socket):
        self.target,self.snapshots,self.staging,self.socket=target,snapshots,staging,socket
        self.prefix=[str(Path(sys.executable).parent/'akdbx'),'--socket',str(socket)]
        self.results={};self.metrics=[];self.intents={}
        for intent in staging.glob('*.json'):
            value=json.loads(intent.read_text())
            op=value['operation_id']
            self.intents[op]=hashlib.sha256((staging/(op+'.kdbx')).read_bytes()).hexdigest()
        self.active=threading.Event();self.finished=threading.Event()
        self.mutation=threading.Lock();self.delay=0;self.metadata_delay=0
        self.queue_metadata=False;self.mode='admit';self.group_verification=admission.GROUP_VERIFICATION

    def command(self,*args):
        done=subprocess.run([*self.prefix,*args],capture_output=True,text=True,timeout=480)
        return json.loads(done.stdout)

    def handler(self):
        lab=self
        class Handler(BaseHTTPRequestHandler):
            def log_message(self,*args): pass
            def reply(self,status,data=b'',**headers):
                try:
                    self.send_response(status);self.send_header('Content-Length',str(len(data)))
                    for key,value in headers.items(): self.send_header(key.replace('_','-'),str(value))
                    self.end_headers()
                    if self.command!='HEAD': self.wfile.write(data)
                except (BrokenPipeError,ConnectionResetError): pass
            def do_GET(self):
                if lab.queue_metadata:
                    with lab.mutation: pass
                time.sleep(lab.metadata_delay)
                data=lab.target.read_bytes()
                self.reply(200,data,ETag='"'+hashlib.sha256(data).hexdigest()+'"')
            do_HEAD=do_GET
            def do_PROPFIND(self):
                if lab.queue_metadata:
                    with lab.mutation: pass
                time.sleep(lab.metadata_delay)
                self.reply(207,b'<multistatus/>')
            def do_PUT(self):
                began=time.monotonic()
                data=self.rfile.read(int(self.headers['Content-Length']))
                body_done=time.monotonic()
                op=self.headers.get('X-Test-Operation') or uuid.uuid4().hex
                if not lab.mutation.acquire(blocking=False):self.reply(423);return
                try:
                    lab.active.set();lab.finished.clear()
                    if op in lab.intents:
                        result=lab.command('merge-status',op)
                    else:
                        source=lab.staging/(op+'.kdbx')
                        fd=os.open(source,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
                        with os.fdopen(fd,'wb') as stream:
                            stream.write(data);stream.flush();os.fsync(stream.fileno())
                        directory=os.open(lab.staging,os.O_RDONLY|os.O_DIRECTORY)
                        try:os.fsync(directory)
                        finally:os.close(directory)
                        lab.intents[op]=hashlib.sha256(data).hexdigest()
                        # Nonsecret durable transport intent. An uncertain CLI
                        # result must reconcile this exact ID, never a new PUT.
                        intent=lab.staging/(op+'.json')
                        with intent.open('x') as stream:
                            os.chmod(intent,0o600);json.dump({'operation_id':op},stream);stream.flush();os.fsync(stream.fileno())
                        directory=os.open(lab.staging,os.O_RDONLY|os.O_DIRECTORY)
                        try:os.fsync(directory)
                        finally:os.close(directory)
                        time.sleep(lab.delay)
                        args=['admit',str(source),'--policy',admission.POLICY,'--snapshot-dir',str(lab.snapshots),'--operation-id',op]
                        args+=['--group-verification',lab.group_verification]
                        if lab.mode=='merge':args=['merge',str(source),'--refresh-target','--preserve-conflicts','--operation-id',op]
                        if self.headers.get('If-Match'):
                            args+=['--if-match',self.headers['If-Match'].strip('"')]
                        rpc=time.monotonic();result=lab.command(*args);rpc_done=time.monotonic()
                        lab.metrics.append({'http_to_body_s':body_done-began,'cli_rpc_s':rpc_done-rpc,'server_s':rpc_done-began,**result.get('timings',{})})
                    lab.results[op]=result
                    okay=result.get('ok') and result.get('state') in {'saved','unchanged'} and result.get('check') is False
                    if lab.mode=='admit':
                        okay=okay and result.get('policy')==admission.POLICY and result.get('verification')==admission.VERIFICATION and result.get('group_protocol')==2 and result.get('group_verification')==lab.group_verification and result.get('group_tag_verification')==('raw-v1' if lab.group_verification==admission.GROUP_VERIFICATION else 'keepassium-2.5.171-sequence-v1') and result.get('group_selection')==('keepassxc-2.7.10-selection-v1' if lab.group_verification==admission.NATIVE_GROUP_VERIFICATION else 'strict-v1') and result.get('exact_bytes') is True
                        okay=okay and self.headers.get('X-Test-Operation',op)==result.get('operation_id')
                        okay=okay and lab.target.read_bytes()==data
                    self.reply(204 if okay else 409)
                finally:
                    lab.active.clear();lab.finished.set();lab.mutation.release()
        return Handler


@contextmanager
def servers(lab):
    backend=ThreadingHTTPServer(('127.0.0.1',0),lab.handler())
    class Proxy(BaseHTTPRequestHandler):
        def log_message(self,*args):pass
        def forward(self):
            body=self.rfile.read(int(self.headers.get('Content-Length',0)))
            # Bounded, measured proxy delay; no claim of TLS/Tailscale coverage.
            time.sleep(0.05)
            conn=HTTPConnection(*backend.server_address,timeout=480)
            try:
                conn.request(self.command,self.path,body=body,headers={k:v for k,v in self.headers.items() if k.lower() not in {'host','connection'}})
                response=conn.getresponse();data=response.read()
                try:
                    self.send_response(response.status)
                    for key,value in response.getheaders():
                        if key.lower() not in {'server','date'}:self.send_header(key,value)
                    self.end_headers();self.wfile.write(data)
                except (BrokenPipeError,ConnectionResetError):pass
            finally:conn.close()
        do_GET=do_HEAD=do_PROPFIND=do_PUT=forward
    proxy=ThreadingHTTPServer(('127.0.0.1',0),Proxy)
    threads=[threading.Thread(target=s.serve_forever,daemon=True) for s in (backend,proxy)]
    for t in threads:t.start()
    try:yield proxy.server_address
    finally:
        for s in (proxy,backend):s.shutdown();s.server_close()
        for t in threads:t.join(2)


def http(address,method,body=None,timeout=30,headers=None):
    conn=HTTPConnection(*address,timeout=timeout)
    try:
        conn.request(method,'/synthetic.kdbx',body=body,headers=headers or {})
        response=conn.getresponse();return response.status,response.read(),dict(response.getheaders())
    finally:conn.close()


class KeePassiumSequence:
    """Public DatabaseSaver sequence: remote SHA512; PUT; cache LOCAL bytes."""
    def __init__(self,address):self.address=address;self.cached=None
    def read(self):
        status,data,_=http(self.address,'GET');assert status==200
        self.cached=hashlib.sha512(data).digest();return data
    def save(self,data,timeout=30,operation=None):
        _,remote,_=http(self.address,'GET',timeout=timeout)
        if hashlib.sha512(remote).digest()!=self.cached:return 'conflict'
        status,_,_=http(self.address,'PUT',data,timeout=timeout,headers={'X-Test-Operation':operation or uuid.uuid4().hex})
        if status==204:self.cached=hashlib.sha512(data).digest()
        return status
