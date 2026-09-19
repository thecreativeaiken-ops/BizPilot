const http=require('http');
const fs=require('fs');
const path=require('path');
const crypto=require('crypto');
const {URL}=require('url');

function loadDotEnv(file){
  try{
    if(!fs.existsSync(file))return;
    for(const line of fs.readFileSync(file,'utf8').split(/\r?\n/)){
      const m=line.match(/^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*?)\s*$/);
      if(m&&!process.env[m[1]])process.env[m[1]]=m[2].replace(/^['"]|['"]$/g,'');
    }
  }catch(e){}
}
loadDotEnv(path.join(__dirname,'.env'));

const ROOT=__dirname;
const PORT=Number(process.env.PORT||3000);
const PUBLIC_BASE_URL=(process.env.PUBLIC_BASE_URL||`http://localhost:${PORT}`).replace(/\/$/,'');
const DATA_DIR=process.env.DATA_DIR||path.join(ROOT,'server-data');
const DB_FILE=path.join(DATA_DIR,'db.json');
const SESSION_DAYS=Number(process.env.SESSION_DAYS||30);
const COOKIE_NAME='bizpilot_session';

if(!fs.existsSync(DATA_DIR))fs.mkdirSync(DATA_DIR,{recursive:true});

function loadDB(){
  if(!fs.existsSync(DB_FILE))return {users:[],sessions:[]};
  try{return JSON.parse(fs.readFileSync(DB_FILE,'utf8'))}
  catch(e){return {users:[],sessions:[]}}
}
let db=loadDB();

function saveDB(){
  const tmp=DB_FILE+'.tmp';
  fs.writeFileSync(tmp,JSON.stringify(db,null,2));
  fs.renameSync(tmp,DB_FILE);
}

function uid(prefix){return prefix+'_'+crypto.randomBytes(12).toString('hex')}

function hashPassword(password,salt=crypto.randomBytes(16).toString('hex')){
  return new Promise((resolve,reject)=>{
    crypto.scrypt(password,salt,64,(e,key)=>e?reject(e):resolve({salt,hash:key.toString('hex')}))
  })
}

async function verifyPassword(password,record){
  const out=await hashPassword(password,record.salt);
  return crypto.timingSafeEqual(
    Buffer.from(out.hash,'hex'),
    Buffer.from(record.passwordHash,'hex')
  );
}

function parseCookies(req){
  const out={};
  for(const part of String(req.headers.cookie||'').split(';')){
    const i=part.indexOf('=');
    if(i>0)out[part.slice(0,i).trim()]=decodeURIComponent(part.slice(i+1).trim());
  }
  return out;
}

function setCookie(res,name,value,maxAge){
  const secure=process.env.NODE_ENV==='production'?'; Secure':'';
  res.setHeader('Set-Cookie',`${name}=${encodeURIComponent(value)}; HttpOnly; SameSite=Lax; Path=/; Max-Age=${maxAge}${secure}`);
}

function clearCookie(res,name){
  const secure=process.env.NODE_ENV==='production'?'; Secure':'';
  res.setHeader('Set-Cookie',`${name}=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0${secure}`);
}

function publicUser(u){
  return {
    id:u.id,
    name:u.name,
    email:u.email,
    createdAt:u.createdAt
  };
}

function authUser(req){
  const sid=parseCookies(req)[COOKIE_NAME];
  if(!sid)return null;
  const session=db.sessions.find(x=>x.id===sid&&new Date(x.expiresAt)>new Date());
  if(!session)return null;
  return db.users.find(u=>u.id===session.userId)||null;
}

function send(res,status,data,headers={}){
  const body=Buffer.from(JSON.stringify(data));
  res.writeHead(status,{
    'Content-Type':'application/json; charset=utf-8',
    'Content-Length':body.length,
    'Cache-Control':'no-store',
    'X-Content-Type-Options':'nosniff',
    'Referrer-Policy':'strict-origin-when-cross-origin',
    ...headers
  });
  res.end(body);
}

function parseBody(req){
  return new Promise((resolve,reject)=>{
    let b='';
    req.on('data',c=>{
      b+=c;
      if(b.length>1e6)req.destroy();
    });
    req.on('end',()=>{
      try{resolve(b?JSON.parse(b):{})}
      catch(e){reject(new Error('Invalid JSON'))}
    });
    req.on('error',reject);
  });
}

function cleanData(d){
  return {
    transactions:Array.isArray(d.transactions)?d.transactions:[],
    customers:Array.isArray(d.customers)?d.customers:[],
    products:Array.isArray(d.products)?d.products:[],
    stockMovements:Array.isArray(d.stockMovements)?d.stockMovements:[],
    invoices:Array.isArray(d.invoices)?d.invoices:[],
    staff:Array.isArray(d.staff)?d.staff:[],
    activity:Array.isArray(d.activity)?d.activity:[],
    settings:d.settings&&typeof d.settings==='object'?d.settings:{}
  };
}

function originOk(req){
  const origin=req.headers.origin;
  if(!origin)return true;
  try{return new URL(origin).origin===new URL(PUBLIC_BASE_URL).origin}
  catch(e){return false}
}

function serveStatic(req,res){
  let pathname=new URL(req.url,'http://localhost').pathname;
  if(pathname==='/')pathname='/index.html';

  const safe=path.normalize(pathname).replace(/^\.+/,'');
  const file=path.join(ROOT,safe);

  if(!file.startsWith(ROOT)||!fs.existsSync(file)||fs.statSync(file).isDirectory()){
    return send(res,404,{error:'Not found'});
  }

  const ext=path.extname(file).toLowerCase();
  const types={
    '.html':'text/html; charset=utf-8',
    '.js':'text/javascript; charset=utf-8',
    '.css':'text/css; charset=utf-8',
    '.json':'application/json; charset=utf-8',
    '.png':'image/png',
    '.ico':'image/x-icon',
    '.svg':'image/svg+xml',
    '.webmanifest':'application/manifest+json'
  };

  res.writeHead(200,{
    'Content-Type':types[ext]||'application/octet-stream',
    'Cache-Control':ext==='.html'||ext==='.js'||ext==='.css'?'no-cache':'public, max-age=86400'
  });
  fs.createReadStream(file).pipe(res);
}

const server=http.createServer(async(req,res)=>{
  try{
    if(!originOk(req))return send(res,403,{error:'Origin not allowed'});

    const u=new URL(req.url,`http://${req.headers.host||'localhost'}`);
    const p=u.pathname;

    if(req.method==='GET'&&p==='/health'){
      return send(res,200,{ok:true,version:'5.0-free',environment:'free'});
    }

    if(p.startsWith('/api/')){
      if(req.method==='POST'&&p==='/api/auth/register'){
        const b=await parseBody(req);
        const name=String(b.name||'').trim();
        const email=String(b.email||'').trim().toLowerCase();
        const password=String(b.password||'');

        if(name.length<2||!email.includes('@')||password.length<8){
          return send(res,400,{error:'Use a valid name, email and password of at least 8 characters.'});
        }

        if(db.users.some(x=>x.email===email)){
          return send(res,409,{error:'An account with that email already exists.'});
        }

        const hp=await hashPassword(password);
        const user={
          id:uid('usr'),
          name,
          email,
          passwordHash:hp.hash,
          salt:hp.salt,
          createdAt:new Date().toISOString(),
          data:cleanData({})
        };

        db.users.push(user);

        const sid=uid('sess');
        db.sessions.push({
          id:sid,
          userId:user.id,
          expiresAt:new Date(Date.now()+SESSION_DAYS*86400000).toISOString()
        });

        saveDB();
        setCookie(res,COOKIE_NAME,sid,SESSION_DAYS*86400);
        return send(res,201,{user:publicUser(user)});
      }

      if(req.method==='POST'&&p==='/api/auth/login'){
        const b=await parseBody(req);
        const email=String(b.email||'').trim().toLowerCase();
        const password=String(b.password||'');
        const user=db.users.find(x=>x.email===email);

        if(!user||!(await verifyPassword(password,user))){
          return send(res,401,{error:'Incorrect email or password.'});
        }

        db.sessions=db.sessions.filter(x=>new Date(x.expiresAt)>new Date());

        const sid=uid('sess');
        db.sessions.push({
          id:sid,
          userId:user.id,
          expiresAt:new Date(Date.now()+SESSION_DAYS*86400000).toISOString()
        });

        saveDB();
        setCookie(res,COOKIE_NAME,sid,SESSION_DAYS*86400);
        return send(res,200,{user:publicUser(user)});
      }

      if(req.method==='POST'&&p==='/api/auth/logout'){
        const sid=parseCookies(req)[COOKIE_NAME];
        db.sessions=db.sessions.filter(x=>x.id!==sid);
        saveDB();
        clearCookie(res,COOKIE_NAME);
        return send(res,200,{ok:true});
      }

      if(req.method==='GET'&&p==='/api/auth/me'){
        const user=authUser(req);
        if(!user)return send(res,401,{error:'Not authenticated'});
        return send(res,200,{user:publicUser(user)});
      }

      if(req.method==='PUT'&&p==='/api/auth/profile'){
        const user=authUser(req);
        if(!user)return send(res,401,{error:'Not authenticated'});
        const b=await parseBody(req);
        user.name=String(b.name||user.name).trim().slice(0,80);
        saveDB();
        return send(res,200,{user:publicUser(user)});
      }

      if((req.method==='GET'||req.method==='PUT')&&p==='/api/data'){
        const user=authUser(req);
        if(!user)return send(res,401,{error:'Not authenticated'});

        if(req.method==='GET'){
          return send(res,200,{data:user.data||cleanData({})});
        }

        const b=await parseBody(req);
        user.data=cleanData(b);
        saveDB();
        return send(res,200,{ok:true});
      }

      return send(res,404,{error:'API endpoint not found.'});
    }

    return serveStatic(req,res);
  }catch(e){
    console.error('BizPilot server error:',e);
    return send(res,500,{error:'Server error.'});
  }
});

server.listen(PORT,'0.0.0.0',()=>{
  console.log(`BizPilot 5.0 Free running on ${PUBLIC_BASE_URL}`);
});
