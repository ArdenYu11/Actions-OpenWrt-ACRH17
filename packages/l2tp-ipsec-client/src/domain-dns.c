#define _POSIX_C_SOURCE 200809L
#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <netinet/in.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define MAX_RULES 512
#define MAX_ROUTES 4096
#define PACKET 65535
#define TABLE "41717"
struct rule { char kind[8], value[254]; };
struct route { char ip[INET_ADDRSTRLEN]; time_t expires; };
static struct rule rules[MAX_RULES];
static struct route routes[MAX_ROUTES];
static size_t rule_count, route_count, route_limit = MAX_ROUTES;
static const char *ip_tool = "/sbin/ip";
static volatile sig_atomic_t stopping;
static unsigned int socket_mark;
static long long io_deadline;

static uint16_t u16(const unsigned char *p) { return (uint16_t)((p[0] << 8) | p[1]); }
static uint32_t u32(const unsigned char *p) { return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3]; }
static time_t now(void) { struct timespec t; clock_gettime(CLOCK_MONOTONIC, &t); return t.tv_sec; }
static long long milliseconds(void) { struct timespec t;clock_gettime(CLOCK_MONOTONIC,&t);return (long long)t.tv_sec*1000+t.tv_nsec/1000000; }
static void lower(char *s) { for (; *s; s++) *s = (char)tolower((unsigned char)*s); }
static void stop_signal(int s) { (void)s; stopping = 1; }

static int match(const char *kind, const char *value, const char *name) {
 size_t n = strlen(name), v = strlen(value);
 if (!strcmp(kind, "exact")) return !strcmp(value, name);
 if (!strcmp(kind, "prefix")) return n >= v && !strncmp(value, name, v);
 if (!strcmp(kind, "suffix")) return n >= v && !strcmp(name + n - v, value) && (n == v || name[n-v-1] == '.');
 return 0;
}

static int matched(const char *name) {
 for (size_t i=0; i<rule_count; i++) if (match(rules[i].kind, rules[i].value, name)) return 1;
 return 0;
}

static int read_rules(const char *path) {
 FILE *f = fopen(path, "r");
 if (!f) return -1;
 char line[300], extra;
 while (fgets(line, sizeof(line), f)) {
  if (rule_count == MAX_RULES || sscanf(line, "%7s %253s %c", rules[rule_count].kind, rules[rule_count].value, &extra) != 2) { fclose(f); return -1; }
  lower(rules[rule_count].value);
  rule_count++;
 }
 fclose(f);
 return 0;
}

static int route_command(const char *action, const char *ip) {
 pid_t pid = fork();
 if (pid == -1) return -1;
 if (!pid) {
  execl(ip_tool, ip_tool, "-4", "route", action, ip, "dev", "l2tp-vpn", "table", TABLE, "proto", "static", "metric", "41718", (char *)NULL);
  _exit(127);
 }
 int status = 0;
 while (waitpid(pid, &status, 0) < 0) if (errno != EINTR) return -1;
 return WIFEXITED(status) && WEXITSTATUS(status) == 0 ? 0 : -1;
}

/* 表满时腾出一个 DNS 有效期已过的位置，选过期最早的。有效期内的地址不动。 */
static int evict_expired(void) {
 time_t t = now();
 size_t oldest = route_count;
 for (size_t i=0; i<route_count; i++)
  if (routes[i].expires <= t && (oldest == route_count || routes[i].expires < routes[oldest].expires)) oldest = i;
 if (oldest == route_count || route_command("del", routes[oldest].ip)) return -1;
 routes[oldest] = routes[--route_count];
 return 0;
}

/* 学到的地址在整个连接期间保留，退出时统一删除。按 DNS TTL 删除会让 SSH 这类长连接
 * 在 TTL 到期后中断；只有表满时才回收已过期的地址。 */
static int add_route(const unsigned char *address, uint32_t ttl) {
 if (address[0] == 0 || address[0] == 127 || address[0] >= 224 || (address[0] == 169 && address[1] == 254)) return 0;
 char ip[INET_ADDRSTRLEN];
 if (!inet_ntop(AF_INET, address, ip, sizeof(ip))) return -1;
 size_t i;
 for (i=0; i<route_count; i++) if (!strcmp(routes[i].ip, ip)) break;
 if (i == route_count) {
  if (route_count >= route_limit && evict_expired()) return -1;
  if (route_command("replace", ip)) return -1;
  i = route_count;
  routes[route_count].expires=0;
  strcpy(routes[route_count++].ip, ip);
 }
 if (ttl < 1) ttl = 1;
 if (ttl > 86400) ttl = 86400;
 time_t expires = now() + ttl + 2;
 if (expires > routes[i].expires) routes[i].expires = expires;
 return 0;
}

/* 解码 DNS 名称，限制压缩指针跳数与输出长度。 */
static int dns_name(const unsigned char *p, size_t size, size_t *offset, char name[254]) {
 size_t pos = *offset, end = 0, used = 0;
 unsigned int jumps = 0;
 while (pos < size && jumps++ < 128) {
  unsigned int len = p[pos++];
  if ((len & 0xc0) == 0xc0) {
   if (pos >= size) return -1;
   if (!end) end = pos+1;
   pos = ((len & 0x3f) << 8) | p[pos];
   continue;
  }
  if (len & 0xc0 || len > 63) return -1;
  if (!len) { name[used] = 0; *offset = end ? end : pos; lower(name); return 0; }
  if (pos + len > size || used + len + (used != 0) > 253) return -1;
  if (used) name[used++] = '.';
  for (unsigned int i=0; i<len; i++) {
   unsigned char ch=p[pos++];
   if (!isalnum(ch) && ch!='-' && ch!='_') return -1;
   name[used++]=(char)ch;
  }
 }
 return -1;
}

static int question(const unsigned char *p, size_t size, char name[254], size_t *end) {
 if (size < 12 || u16(p+4) != 1 || (p[2] & 0x78)) return -1;
 *end = 12;
 if (dns_name(p, size, end, name) || *end+4 > size) return -1;
 *end += 4;
 return 0;
}

static size_t error_reply(unsigned char *p, size_t end, int code) {
 p[2] = (unsigned char)(0x80 | (p[2] & 1));
 p[3] = (unsigned char)(0x80 | code);
 memset(p+6, 0, 6);
 return end;
}

/* 只学习问题域名及其 CNAME 链，完整解析成功后才安装路由。 */
static int learn(unsigned char *p, size_t size) {
 struct answer { char name[254], target[254]; size_t offset; uint16_t type, cls, length; uint32_t ttl; };
 char original[254]; size_t offset;
 if (question(p, size, original, &offset) || (p[3] & 15) || (p[2] & 2)) return -1;
 unsigned int count=u16(p+6);
 if (count>512) return -1;
 struct answer *a=calloc(count ? count : 1,sizeof(*a));
 if (!a) return -1;
 int result=-1;
 for (unsigned int i=0;i<count;i++) {
  if (dns_name(p,size,&offset,a[i].name) || offset+10>size) goto done;
  a[i].type=u16(p+offset);a[i].cls=u16(p+offset+2);a[i].ttl=u32(p+offset+4);a[i].length=u16(p+offset+8);
  offset+=10;a[i].offset=offset;
  if (offset+a[i].length>size) goto done;
  if (a[i].type==5 && a[i].cls==1) {
   size_t end=offset;
   if (dns_name(p,size,&end,a[i].target) || end!=offset+a[i].length) goto done;
  }
  if (a[i].type==1 && a[i].cls==1 && a[i].length!=4) goto done;
  offset+=a[i].length;
 }
 char current[254];strcpy(current,original);
 uint32_t chain_ttl=UINT32_MAX;
 for (unsigned int hops=0;hops<=count;hops++) {
  int next=-1;
  for (unsigned int i=0;i<count;i++) if (a[i].cls==1 && !strcmp(a[i].name,current) && a[i].type==5) { next=(int)i;break; }
  if (next<0) {
   for (unsigned int i=0;i<count;i++) if (a[i].cls==1 && a[i].type==1 && !strcmp(a[i].name,current)) {
    uint32_t ttl=a[i].ttl<chain_ttl ? a[i].ttl : chain_ttl;
    /* 限制回包 TTL，与动态路由有效期一致。 */
    if(ttl>86400)ttl=86400;
    size_t t=a[i].offset-6;
    p[t]=(unsigned char)(ttl>>24);p[t+1]=(unsigned char)(ttl>>16);p[t+2]=(unsigned char)(ttl>>8);p[t+3]=(unsigned char)ttl;
    if (add_route(p+a[i].offset,ttl)) { fputs("域名路由安装失败或达到容量上限。\n",stderr);goto done; }
   }
   result=0;goto done;
  }
  if (a[next].ttl<chain_ttl) chain_ttl=a[next].ttl;
  strcpy(current,a[next].target);
 }
 done: free(a);return result;
}

static int wait_fd(int fd, short events) {
 struct pollfd p={fd,events,0};
 int r;
 int remaining=(int)(io_deadline-milliseconds());
 if(remaining<=0 || stopping)return -1;
 do r=poll(&p,1,remaining); while (r<0 && errno==EINTR && !stopping);
 return r>0 && (p.revents & events) ? 0 : -1;
}

static int read_all(int fd, unsigned char *p, size_t n) {
 while (n && !stopping) {
  if (wait_fd(fd,POLLIN)) return -1;
  ssize_t r=recv(fd,p,n,0);
  if (r<=0) return -1;
  p+=r; n-=(size_t)r;
 }
 return n ? -1 : 0;
}

static int write_all(int fd, const unsigned char *p, size_t n) {
 while (n && !stopping) {
  if (wait_fd(fd,POLLOUT)) return -1;
  ssize_t r=send(fd,p,n,0);
  if (r<=0) return -1;
  p+=r; n-=(size_t)r;
 }
 return n ? -1 : 0;
}

static int upstream(const struct sockaddr_in *server, const unsigned char *query, size_t qsize, unsigned char *reply, int tcp) {
 int fd=socket(AF_INET,tcp ? SOCK_STREAM : SOCK_DGRAM,0), result=-1;
 if (fd<0) return -1;
 struct timeval timeout={2,0};
#ifdef __linux__
 if (socket_mark && setsockopt(fd,SOL_SOCKET,36,&socket_mark,sizeof(socket_mark))) goto done;
#endif
 setsockopt(fd,SOL_SOCKET,SO_SNDTIMEO,&timeout,sizeof(timeout));
 setsockopt(fd,SOL_SOCKET,SO_RCVTIMEO,&timeout,sizeof(timeout));
 if (connect(fd,(const struct sockaddr *)server,sizeof(*server))) goto done;
 if (tcp) {
  unsigned char length[2]={(unsigned char)(qsize>>8),(unsigned char)qsize};
  if (write_all(fd,length,2) || write_all(fd,query,qsize) || read_all(fd,length,2)) goto done;
  result=u16(length);
  if (result<12 || read_all(fd,reply,(size_t)result)) result=-1;
 } else if (send(fd,query,qsize,0)==(ssize_t)qsize && !wait_fd(fd,POLLIN)) {
  result=(int)recv(fd,reply,PACKET,0);
 }
done:
 close(fd); return result;
}

static int address(const char *ip, int port, struct sockaddr_in *out) {
 memset(out,0,sizeof(*out));out->sin_family=AF_INET;out->sin_port=htons((uint16_t)port);
 return inet_pton(AF_INET,ip,&out->sin_addr)==1 ? 0 : -1;
}

static int serve(unsigned char *query, size_t size, unsigned char *reply, int tcp, int full,
                 const struct sockaddr_in *vpn, const struct sockaddr_in *local_dns) {
 char name[254], rname[254]; size_t end, rend;
 if(question(query,size,name,&end) || (query[2]&0x80)) return -1;
 int use_vpn=full || matched(name);
 io_deadline=milliseconds()+2500;
 uint16_t type=u16(query+end-4);
 /* IPv4 VPN 不转发匹配规则的 AAAA，避免客户端绕过 IPv4 路由。 */
 if(use_vpn && (type==28 || type==64 || type==65 || type==255)) { memcpy(reply,query,end);return (int)error_reply(reply,end,0); }
 int result=-1;
 if(use_vpn) result=upstream(vpn,query,size,reply,tcp);
 else result=upstream(local_dns,query,size,reply,tcp);
 if(result<12 || !(reply[2]&0x80) || u16(query)!=u16(reply) || question(reply,(size_t)result,rname,&rend) ||
    strcmp(name,rname) || u16(query+end-4)!=u16(reply+rend-4) || u16(query+end-2)!=u16(reply+rend-2)) {
  memcpy(reply,query,end);return (int)error_reply(reply,end,2);
 }
 if(use_vpn && !full && !(reply[2]&2) && !(reply[3]&15) && learn(reply,(size_t)result)) {
  memcpy(reply,query,end);return (int)error_reply(reply,end,2);
 }
 return result;
}

int main(int argc, char **argv) {
 if(argc==5 && !strcmp(argv[1],"--match")) {
  char value[254],name[254];
  if(strlen(argv[3])>253 || strlen(argv[4])>253)return 2;
  strcpy(value,argv[3]);strcpy(name,argv[4]);lower(value);lower(name);
  puts(match(argv[2],value,name)?"yes":"no");return 0;
 }
 const char *rule_file=NULL,*vpn_ip=NULL,*listen_ip="127.0.0.1",*local_ip="127.0.0.1",*ready_file=NULL;
 int port=1053,vpn_port=53,local_port=53,full=0;
 for(int i=1;i<argc;i+=2) {
  if(i+1==argc)return 2;
  if(!strcmp(argv[i],"--rules"))rule_file=argv[i+1];
  else if(!strcmp(argv[i],"--vpn-dns"))vpn_ip=argv[i+1];
  else if(!strcmp(argv[i],"--ready"))ready_file=argv[i+1];
  else if(!strcmp(argv[i],"--listen"))listen_ip=argv[i+1];
  else if(!strcmp(argv[i],"--local-dns"))local_ip=argv[i+1];
  else if(!strcmp(argv[i],"--mark"))socket_mark=(unsigned int)strtoul(argv[i+1],NULL,0);
  else if(!strcmp(argv[i],"--mode")) { if(strcmp(argv[i+1],"full") && strcmp(argv[i+1],"rules"))return 2;full=!strcmp(argv[i+1],"full"); }
  else if(!strcmp(argv[i],"--port"))port=atoi(argv[i+1]);
  else if(!strcmp(argv[i],"--vpn-port"))vpn_port=atoi(argv[i+1]);
  else if(!strcmp(argv[i],"--local-port"))local_port=atoi(argv[i+1]);
  else if(!strcmp(argv[i],"--ip-tool"))ip_tool=argv[i+1];
  else if(!strcmp(argv[i],"--max-routes")) { long n=strtol(argv[i+1],NULL,10); if(n<1 || n>MAX_ROUTES)return 2; route_limit=(size_t)n; }
  else return 2;
 }
 struct sockaddr_in vpn,local_dns;
 struct sockaddr_storage local;
 memset(&local,0,sizeof(local));
 int family=strchr(listen_ip,':') ? AF_INET6 : AF_INET;
 socklen_t local_size;
 if(family==AF_INET6) { struct sockaddr_in6 *v6=(struct sockaddr_in6 *)&local;v6->sin6_family=AF_INET6;v6->sin6_port=htons((uint16_t)port);local_size=sizeof(*v6);if(inet_pton(AF_INET6,listen_ip,&v6->sin6_addr)!=1)return 2; }
 else { local_size=sizeof(struct sockaddr_in);if(address(listen_ip,port,(struct sockaddr_in *)&local))return 2; }
 if(!rule_file || !vpn_ip || port<1 || port>65535 || vpn_port<1 || vpn_port>65535 || local_port<1 || local_port>65535 || read_rules(rule_file) || address(vpn_ip,vpn_port,&vpn) || address(local_ip,local_port,&local_dns))return 2;
 signal(SIGTERM,stop_signal);signal(SIGINT,stop_signal);signal(SIGPIPE,SIG_IGN);
 int udp=socket(family,SOCK_DGRAM,0),tcp=socket(family,SOCK_STREAM,0),yes=1;
 setsockopt(tcp,SOL_SOCKET,SO_REUSEADDR,&yes,sizeof(yes));
 if(family==AF_INET6) { int no=0;setsockopt(udp,IPPROTO_IPV6,IPV6_V6ONLY,&no,sizeof(no));setsockopt(tcp,IPPROTO_IPV6,IPV6_V6ONLY,&no,sizeof(no)); }
 if(udp<0 || tcp<0 || bind(udp,(struct sockaddr *)&local,local_size) || bind(tcp,(struct sockaddr *)&local,local_size) || listen(tcp,8))return 1;
 unsigned char *query=malloc(PACKET),*reply=malloc(PACKET);
 if(!query || !reply)return 1;
 if(ready_file) { FILE *f=fopen(ready_file,"w");if(!f)return 1;fclose(f); }
 while(!stopping) {
  struct pollfd fds[2]={{udp,POLLIN,0},{tcp,POLLIN,0}};
  int ready=poll(fds,2,1000);
  if(ready<=0)continue;
  if(fds[0].revents&POLLIN) {
   struct sockaddr_storage client;socklen_t len=sizeof(client);
   ssize_t size=recvfrom(udp,query,PACKET,0,(struct sockaddr *)&client,&len);
   int result=size>0 ? serve(query,(size_t)size,reply,0,full,&vpn,&local_dns) : -1;
   if(result>0)sendto(udp,reply,(size_t)result,0,(struct sockaddr *)&client,len);
  }
  if(fds[1].revents&POLLIN) {
   int client=accept(tcp,NULL,NULL);
   if(client<0)continue;
   unsigned char length[2];
   io_deadline=milliseconds()+2500;
   if(!read_all(client,length,2)) {
    size_t size=u16(length);
    if(size>=12 && !read_all(client,query,size)) {
     int result=serve(query,size,reply,1,full,&vpn,&local_dns);
     if(result>0) { length[0]=(unsigned char)(result>>8);length[1]=(unsigned char)result;write_all(client,length,2);write_all(client,reply,(size_t)result); }
    }
   }
   close(client);
  }
 }
 for(size_t i=0;i<route_count;i++)route_command("del",routes[i].ip);
 if(ready_file)unlink(ready_file);
 close(udp);close(tcp);free(query);free(reply);return 0;
}
