using ChomcioRecovery.Chomikuj;
using ChomcioRecovery.Core;
using System.Net;
using System.Xml;
using System.Xml.Linq;

internal static class LargeFolderScenarios
{
    internal static async Task Run(string root,Action<bool,string> check)
    {
        if(Directory.Exists(root))throw new IOException("Use a new fixture directory.");
        Directory.CreateDirectory(root);
        using(var server=new Server())
        using(var client=new ChomikujClient(server))
        {
            await client.LoginAsync("synthetic-user","synthetic-password",default);
            var remote=client.OpenFolder(new("7","Synthetic"));
            var names=await remote.ListNamesAsync(default);
            check(server.ListBytes>2*1024*1024&&server.ListBytes<64*1024*1024,"regression exercises a complete folder response above the old quota");
            check(names.Count==3000&&names.Distinct().Count()==3000&&names[0]=="repo.json"&&names[^1]==Server.Name(3000),"all names including the tail are retained");
            check(server.Lists==1&&server.FileRequests==0&&server.Gets==0,"name-only discovery still performs no payload probes");
            var files=await remote.ListAsync(default);
            check(files.Count==3000&&files.All(f=>f.Length==3),"full listing resolves exact sizes beyond SOAP hints");
            check(server.FileRequests==3000&&server.Gets==3000,"large folder retains every required exact-length probe");
            using var bytes=new MemoryStream();await remote.DownloadAsync(files[^1],bytes,3,default);
            check(bytes.ToArray().SequenceEqual(new byte[]{1,2,3}),"last listed object still supports complete readback");
            check(server.Mutations==0,"large folder reads never create or send anything");
        }
        foreach(string mode in new[]{"bad-tail","duplicate-tail","dtd"})
        {
            using var server=new Server(mode);using var client=new ChomikujClient(server);
            await client.LoginAsync("synthetic-user","synthetic-password",default);
            Exception? failure=null;
            try{await new CloudVaultTransfer(client.OpenFolder(new("7","Synthetic"))).ListSnapshotsAsync(default);}
            catch(Exception e)when(e is InvalidDataException or XmlException){failure=e;}
            check(failure is not null,"large malformed or ambiguous document is rejected: "+mode);
            check(server.Lists==1&&server.FileRequests==0&&server.Gets==0&&server.Mutations==0,"rejection is complete, non-mutating and not retried: "+mode);
        }
        foreach(string mode in new[]{"folder-overflow","auth-overflow","folders-overflow","file-overflow"})
        {
            using var server=new Server(mode);using var client=new ChomikujClient(server);
            InvalidDataException? failure=null;
            try
            {
                await client.LoginAsync("synthetic-user","synthetic-password",default);
                var remote=client.OpenFolder(new("7","Synthetic"));
                if(mode=="folders-overflow")await client.ListFoldersAsync(default);
                else if(mode=="file-overflow")
                {
                    using var output=new MemoryStream();
                    // A server-controlled ID shaped like a folder must not
                    // promote an individual record to the larger quota.
                    await remote.DownloadAsync(new("/untrusted/","repo.json",3),output,3,default);
                }
                else await remote.ListNamesAsync(default);
            }
            catch(InvalidDataException e){failure=e;}
            var detail=failure is null?null:ChomikujClient.GetResponseFailure(failure);
            check(detail?.Reason.ToString()=="SoapBodyTooLarge"&&detail.Operation==ChomikujClient.HttpOperation.SoapRequest,"bounded overflow has safe context: "+mode);
            long limit=mode=="folder-overflow"?64L*1024*1024:2L*1024*1024;
            check(server.OverflowCalls==1&&server.OverflowStream is {ReadCount:>0} stream&&stream.ReadCount>limit&&stream.ReadCount<=limit+16384,
                "actual bytes enforce the proper finite quota despite false small Content-Length: "+mode);
            check(server.Mutations==0&&server.Gets==0,"overflow causes no data request or write: "+mode);
        }
        using(var cancel=new CancellationTokenSource())
        using(var server=new Server("cancel",cancel))
        using(var client=new ChomikujClient(server))
        {
            await client.LoginAsync("synthetic-user","synthetic-password",cancel.Token);
            bool cancelled=false;
            try{await client.OpenFolder(new("7","Synthetic")).ListNamesAsync(cancel.Token);}
            catch(OperationCanceledException){cancelled=true;}
            check(cancelled&&server.OverflowCalls==1,"caller cancellation interrupts a large response without another attempt");
            check(server.OverflowStream!.ReadCount<2*1024*1024&&server.Mutations==0,"cancelled read stops before buffering the document");
        }
        Console.WriteLine("CHOMCIO_LARGE_FOLDER=PASS (synthetic transport only)");
    }
    private sealed class Server(string mode="valid",CancellationTokenSource? cancel=null):HttpMessageHandler
    {
        internal int Lists,FileRequests,Gets,Mutations,OverflowCalls,ListBytes;
        internal RepeatStream? OverflowStream;
        internal static string Name(int i)=>i==1?"repo.json":i.ToString("x64")+".obj";
        private static string Entry(int i)=>$"<FileEntry><id>{i}</id><name>{Name(i)}</name><size>1</size><url>https://download.chomikuj.pl/synthetic</url></FileEntry>";
        private HttpResponseMessage Overflow(bool folder)
        {
            OverflowCalls++;
            OverflowStream=new RepeatStream((folder?64L:2L)*1024*1024+1,cancel);
            var content=new StreamContent(OverflowStream);content.Headers.ContentLength=1;
            return new(HttpStatusCode.OK){Content=content};
        }
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request,CancellationToken token)
        {
            if(request.RequestUri!.Host=="download.chomikuj.pl")
            {Gets++;return new(HttpStatusCode.OK){Content=new ByteArrayContent(new byte[]{1,2,3})};}
            string action=request.Headers.GetValues("SOAPAction").Single().Split('/')[^1];
            var body=XDocument.Parse(await request.Content!.ReadAsStringAsync(token));string payload;
            if(action=="Auth")
            {if(mode=="auth-overflow")return Overflow(false);payload="<token>synthetic</token><hamsterId>123</hamsterId><hamsterName>synthetic-user</hamsterName>";}
            else if(action=="Folders")
            {if(mode=="folders-overflow")return Overflow(false);payload="<folder><folders/></folder>";}
            else if(action=="Download")
            {
                string id=body.Descendants().Single(e=>e.Name.LocalName=="id").Value;
                if(mode=="file-overflow"){FileRequests++;return Overflow(false);}
                if(id.StartsWith('/'))
                {
                    Lists++;if(mode is "folder-overflow" or "cancel")return Overflow(true);
                    string padding=new('x',800);
                    payload="<list><DownloadFolder><files>"+string.Concat(Enumerable.Range(1,3000).Select(i=>
                        i==3000&&mode=="bad-tail"?"<Unexpected/>":Entry(i==3000&&mode=="duplicate-tail"?1:i).Replace("</FileEntry>","<metadata>"+padding+"</metadata></FileEntry>")))+"</files></DownloadFolder></list>";
                }
                else{FileRequests++;payload="<list><DownloadFolder><files>"+Entry(int.Parse(id))+"</files></DownloadFolder></list>";}
            }
            else{Mutations++;throw new InvalidOperationException("Unexpected write");}
            string xml=$"<Envelope><Body><{action}Response><{action}Result><status>Ok</status>{payload}</{action}Result></{action}Response></Body></Envelope>";
            if(action=="Download"&&payload.Length>2*1024*1024){ListBytes=System.Text.Encoding.UTF8.GetByteCount(xml);if(mode=="dtd")xml="<!DOCTYPE Envelope [<!ENTITY unexpected SYSTEM 'file:///never-read'>]>"+xml;}
            return new(HttpStatusCode.OK){Content=new StringContent(xml)};
        }
    }
    private sealed class RepeatStream(long length,CancellationTokenSource? cancel):Stream
    {
        internal long ReadCount;
        public override bool CanRead=>true;public override bool CanSeek=>false;public override bool CanWrite=>false;
        public override long Length=>throw new NotSupportedException();public override long Position{get=>ReadCount;set=>throw new NotSupportedException();}
        public override int Read(byte[] buffer,int offset,int count)
        {int n=(int)Math.Min(count,length-ReadCount);Array.Fill(buffer,(byte)' ',offset,n);ReadCount+=n;return n;}
        public override ValueTask<int> ReadAsync(Memory<byte> buffer,CancellationToken token=default)
        {if(cancel is not null&&ReadCount>=65536)cancel.Cancel();token.ThrowIfCancellationRequested();int n=(int)Math.Min(buffer.Length,length-ReadCount);buffer.Span[..n].Fill((byte)' ');ReadCount+=n;return ValueTask.FromResult(n);}
        public override void Flush()=>throw new NotSupportedException();public override long Seek(long o,SeekOrigin s)=>throw new NotSupportedException();
        public override void SetLength(long l)=>throw new NotSupportedException();public override void Write(byte[] b,int o,int c)=>throw new NotSupportedException();
    }
}
