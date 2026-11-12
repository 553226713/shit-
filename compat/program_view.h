/* Optional compatibility dispatch. Core callbacks know no executable names.
 * The selected module registry supplies the raw-client and script lists. */
static unsigned compat_length(const char *s) { unsigned n=0;while(s[n])n++;return n; }
static const char *compat_basename(const char *s) {
    const char *name=s;for(;*s;s++)if(*s=='/')name=s+1;return name;
}
static int compat_match(const char *patterns, const char *name) {
    if(!patterns || !*patterns)return 0;
    unsigned length=compat_length(name);
    while(*patterns) {
        unsigned n=0;while(patterns[n] && patterns[n]!=',')n++;
        unsigned compare=n;
        int prefix=n && patterns[n-1]=='*';
        if(prefix)compare--;
        if((prefix?length>=compare:length==compare)) {
            unsigned i=0;while(i<compare && patterns[i]==name[i])i++;
            if(i==compare)return 1;
        }
        patterns+=n;if(*patterns)patterns++;
    }
    return 0;
}
static int compat_raw_view(void) {
    const char *clients=scope_env("YT_COMPAT_RAW_CLIENTS");
    const char *scripts=scope_env("YT_COMPAT_SCRIPT_CLIENTS");
    if((!clients || !*clients) && (!scripts || !*scripts))return 0;
    struct context *ctx=((struct context *(*)(void))0x417490)();
    if(ctx->pid<=0)return 0;
    char path[64]="/proc/",digits[16],args[4096];
    unsigned pid=ctx->pid,n=0,length=6;
    do {digits[n++]='0'+pid%10;pid/=10;}while(pid);
    while(n)path[length++]=digits[--n];
    const char exe[]="/exe";
    for(unsigned i=0;i<sizeof(exe);i++)path[length+i]=exe[i];
    long got=call6(SYS_readlinkat,AT_FDCWD,(long)path,(long)args,sizeof(args)-1,0,0);
    if(got<=0)return 0;
    args[got]=0;
    const char *name=compat_basename(args);
    if(compat_match(clients,name))return 1;
    if(!scripts || !*scripts || !compat_match("python*",name))return 0;
    const char cmdline[]="/cmdline";
    for(unsigned i=0;i<sizeof(cmdline);i++)path[length+i]=cmdline[i];
    int fd=raw_open(path,O_RDONLY,0);if(fd<0)return 0;
    got=SC(read,fd,args,sizeof(args)-1);close_fd(fd);
    if(got<=0)return 0;
    args[got]=0;
    unsigned at=0;while(at<(unsigned)got && args[at])at++;at++;
    while(at<(unsigned)got) {
        const char *arg=args+at;
        unsigned len=compat_length(arg);at+=len+1;
        if(!len)return 0;
        if(arg[0]!='-')return compat_match(scripts,compat_basename(arg));
        if((arg[1]=='c' || arg[1]=='m') && !arg[2])return 0;
        if((arg[1]=='W' || arg[1]=='X') && !arg[2]) {
            if(at>=(unsigned)got)return 0;
            at+=compat_length(args+at)+1;
        }
    }
    return 0;
}
