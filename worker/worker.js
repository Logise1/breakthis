const SECRET_KEY = 'BrKTh!s_H4CK_2024_s3cr3t_k3y_x9z7';
const CORS = {'Access-Control-Allow-Origin':'*','Access-Control-Allow-Methods':'GET,POST,OPTIONS','Access-Control-Allow-Headers':'Content-Type,Authorization','Content-Type':'application/json'};

// Secretos de cada nivel — SOLO en el servidor
const LEVELS = {
  6: { cookie: 'xK9_r00t_4cc3ss' },
  7: { pin: 7341 },
  8: { code: 'pr1v_3sc_x7' },
  9: { password: 'Sh4d0w_Pr0t0c0l!' }
};

async function sign(msg) {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey('raw',enc.encode(SECRET_KEY),{name:'HMAC',hash:'SHA-256'},false,['sign']);
  const sig = await crypto.subtle.sign('HMAC',key,enc.encode(msg));
  return[...new Uint8Array(sig)].map(b=>b.toString(16).padStart(2,'0')).join('');
}

async function seal(id) {
  const n = crypto.randomUUID().slice(0,8);
  return n+'.'+(await sign('bt_'+id+'_'+n)).slice(0,16);
}

function json(data,h={}) { return new Response(JSON.stringify(data),{headers:{...CORS,...h}}); }
function err(data,s=400) { return new Response(JSON.stringify(data),{status:s,headers:CORS}); }

export default {
  async fetch(request) {
    const url = new URL(request.url);
    if (request.method==='OPTIONS') return new Response(null,{status:204,headers:CORS});

    // ── Genérico: completar retos 3,4,5,10 ──
    if (url.pathname==='/api/complete'&&request.method==='POST') {
      try {
        const {challenge}=await request.json();
        const id=parseInt(challenge);
        if(!id||![3,4,5,10].includes(id)) return err({error:'Use level-specific endpoints'});
        return json({token:await seal(id)});
      } catch(e) { return err({error:'Bad request'}); }
    }

    // ── Batch verify (para el index.html) ──
    if (url.pathname==='/api/verify-batch'&&request.method==='POST') {
      try {
        const {tokens}=await request.json();
        const results={};
        for(const[id,token] of Object.entries(tokens||{})){
          const c=parseInt(id);
          if(!token||isNaN(c)){results[id]=false;continue}
          const p=token.split('.');
          if(p.length!==2){results[id]=false;continue}
          results[id]=(await sign('bt_'+c+'_'+p[0])).slice(0,16)===p[1];
        }
        return json({results});
      } catch(e) { return json({results:{}}); }
    }

    // ════════════════════════════════════════════
    //  LEVEL 6 — Cookie Monster
    //  El valor secreto de la cookie está oculto
    //  en los HEADERS de respuesta de /config
    // ════════════════════════════════════════════
    if (url.pathname==='/api/level/6/config') {
      return new Response(
        JSON.stringify({message:'El valor de la cookie no es "admin". Inspecciona los HEADERS de esta respuesta.'}),
        {headers:{...CORS,'X-Admin-Cookie-Value':LEVELS[6].cookie}}
      );
    }
    if (url.pathname==='/api/level/6/verify'&&request.method==='POST') {
      try {
        const {value}=await request.json();
        if(value===LEVELS[6].cookie) return json({success:true,token:await seal(6)});
        return json({success:false,hint:'Llama a GET /api/level/6/config y mira los Response Headers'});
      } catch(e) { return err({success:false}); }
    }

    // ════════════════════════════════════════════
    //  LEVEL 7 — Token Falsificado
    //  Necesitas user, role Y un pin secreto.
    //  El pin requiere Authorization header.
    // ════════════════════════════════════════════
    if (url.pathname==='/api/level/7/requirements') {
      return json({
        required_fields:['user','role','pin'],
        known_values:{user:'admin',role:'superuser',pin:'???'},
        hint:'GET /api/level/7/pin (requiere header Authorization: Bearer breakthis)'
      });
    }
    if (url.pathname==='/api/level/7/pin') {
      if(request.headers.get('Authorization')!=='Bearer breakthis')
        return err({error:'Unauthorized. Necesitas: Authorization: Bearer breakthis'},401);
      return json({pin:LEVELS[7].pin});
    }
    if (url.pathname==='/api/level/7/verify'&&request.method==='POST') {
      try {
        const {session}=await request.json();
        if(session?.user==='admin'&&session?.role==='superuser'&&session?.pin===LEVELS[7].pin)
          return json({success:true,token:await seal(7)});
        return json({success:false,hint:'Revisa /api/level/7/requirements'});
      } catch(e) { return err({success:false}); }
    }

    // ════════════════════════════════════════════
    //  LEVEL 8 — Escalada de Privilegios
    //  Cambiar el rol no basta. Necesitas un
    //  código de acceso del endpoint /access-code
    // ════════════════════════════════════════════
    if (url.pathname==='/api/level/8/access-code'&&request.method==='POST') {
      try {
        const {role}=await request.json();
        if(role==='admin') return json({access_code:LEVELS[8].code});
        return err({error:'Forbidden: solo admins pueden obtener el código'},403);
      } catch(e) { return err({error:'Envía JSON con {role:"admin"}'}); }
    }
    if (url.pathname==='/api/level/8/verify'&&request.method==='POST') {
      try {
        const {role,code}=await request.json();
        if(role==='admin'&&code===LEVELS[8].code) return json({success:true,token:await seal(8)});
        return json({success:false,hint:'POST /api/level/8/access-code con {role:"admin"}'});
      } catch(e) { return err({success:false}); }
    }

    // ════════════════════════════════════════════
    //  LEVEL 9 — Mensaje Cifrado
    //  La contraseña se sirve codificada desde
    //  el servidor, NO está en el HTML
    // ════════════════════════════════════════════
    if (url.pathname==='/api/level/9/cipher') {
      return json({cipher:btoa(LEVELS[9].password),encoding:'base64'});
    }
    if (url.pathname==='/api/level/9/verify'&&request.method==='POST') {
      try {
        const {password}=await request.json();
        if(password===LEVELS[9].password) return json({success:true,token:await seal(9)});
        return json({success:false,hint:'Decodifica el cipher de GET /api/level/9/cipher con atob()'});
      } catch(e) { return err({success:false}); }
    }

    return json({name:'Break This API',v:'1.0'});
  }
};
