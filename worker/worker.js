const SECRET_KEY = 'BrKTh!s_H4CK_2024_s3cr3t_k3y_x9z7';
const CORS = {'Access-Control-Allow-Origin':'*','Access-Control-Allow-Methods':'POST, OPTIONS','Access-Control-Allow-Headers':'Content-Type','Content-Type':'application/json'};

async function sign(msg) {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey('raw',enc.encode(SECRET_KEY),{name:'HMAC',hash:'SHA-256'},false,['sign']);
  const sig = await crypto.subtle.sign('HMAC',key,enc.encode(msg));
  return[...new Uint8Array(sig)].map(b=>b.toString(16).padStart(2,'0')).join('');
}

export default {
  async fetch(request) {
    const url = new URL(request.url);
    if (request.method==='OPTIONS') return new Response(null,{status:204,headers:CORS});

    if (url.pathname==='/api/complete'&&request.method==='POST') {
      const {challenge}=await request.json();
      const id=parseInt(challenge);
      if(!id||id<3||id>10) return new Response(JSON.stringify({error:'Invalid'}),{status:400,headers:CORS});
      const nonce=crypto.randomUUID().slice(0,8);
      const sig=await sign('bt_'+id+'_'+nonce);
      return new Response(JSON.stringify({token:nonce+'.'+sig.slice(0,16)}),{headers:CORS});
    }

    if (url.pathname==='/api/verify-batch'&&request.method==='POST') {
      const {tokens}=await request.json();
      const results={};
      for(const[id,token] of Object.entries(tokens||{})){
        const cid=parseInt(id);
        if(!token||isNaN(cid)){results[id]=false;continue}
        const p=token.split('.');
        if(p.length!==2){results[id]=false;continue}
        const sig=await sign('bt_'+cid+'_'+p[0]);
        results[id]=sig.slice(0,16)===p[1];
      }
      return new Response(JSON.stringify({results}),{headers:CORS});
    }

    return new Response(JSON.stringify({name:'Break This API',v:'1.0'}),{headers:CORS});
  }
};
