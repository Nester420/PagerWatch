// SPDX-License-Identifier: GPL-3.0-or-later
// Generate private per-installation TLS material with Go's standard library.
package main
import("crypto/ecdsa";"crypto/elliptic";"crypto/rand";"crypto/x509";"crypto/x509/pkix";"encoding/pem";"fmt";"math/big";"net";"os";"path/filepath";"time")
func serial()*big.Int{n,e:=rand.Int(rand.Reader,new(big.Int).Lsh(big.NewInt(1),128));if e!=nil{panic(e)};return n}
func write(dir,name,kind string,data []byte,mode os.FileMode){if e:=os.WriteFile(filepath.Join(dir,name),pem.EncodeToMemory(&pem.Block{Type:kind,Bytes:data}),mode);e!=nil{panic(e)}}
func main(){if len(os.Args)!=3{panic("usage: pw-certgen directory management-IP")};dir,host:=os.Args[1],os.Args[2];ip:=net.ParseIP(host);if ip==nil{panic("management IP required")};if e:=os.MkdirAll(dir,0700);e!=nil{panic(e)}
 ca,e:=ecdsa.GenerateKey(elliptic.P256(),rand.Reader);if e!=nil{panic(e)};key,e:=ecdsa.GenerateKey(elliptic.P256(),rand.Reader);if e!=nil{panic(e)}
 before:=time.Date(2020,1,1,0,0,0,0,time.UTC);after:=time.Date(2036,1,1,0,0,0,0,time.UTC)
 root:=&x509.Certificate{SerialNumber:serial(),Subject:pkix.Name{CommonName:"PagerWatch Local CA"},NotBefore:before,NotAfter:after,IsCA:true,BasicConstraintsValid:true,MaxPathLen:0,MaxPathLenZero:true,KeyUsage:x509.KeyUsageCertSign|x509.KeyUsageCRLSign}
 rootDER,e:=x509.CreateCertificate(rand.Reader,root,root,&ca.PublicKey,ca);if e!=nil{panic(e)}
 leaf:=&x509.Certificate{SerialNumber:serial(),Subject:pkix.Name{CommonName:"PagerWatch"},NotBefore:before,NotAfter:after,BasicConstraintsValid:true,KeyUsage:x509.KeyUsageDigitalSignature,ExtKeyUsage:[]x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},IPAddresses:[]net.IP{ip,net.ParseIP("127.0.0.1")},DNSNames:[]string{"localhost","pagerwatch.local"}}
 leafDER,e:=x509.CreateCertificate(rand.Reader,leaf,root,&key.PublicKey,ca);if e!=nil{panic(e)}
 caKey,e:=x509.MarshalPKCS8PrivateKey(ca);if e!=nil{panic(e)};leafKey,e:=x509.MarshalPKCS8PrivateKey(key);if e!=nil{panic(e)}
 write(dir,"ca.pem","CERTIFICATE",rootDER,0644);write(dir,"ca-key.pem","PRIVATE KEY",caKey,0600);write(dir,"server.pem","CERTIFICATE",leafDER,0644);write(dir,"server-key.pem","PRIVATE KEY",leafKey,0600)
 if e=os.WriteFile(filepath.Join(dir,"host.txt"),[]byte(host),0600);e!=nil{panic(e)};fmt.Println("TLS certificate created")
}
