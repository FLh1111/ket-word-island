// Only the public project URL and publishable key may be configured here.
const cloudConfig=window.ISLAND_CONFIG||{};
const teacherKey='island-teacher-auth',studentKey='island-student-token';
const cloudStorage=sessionStorage;
function savedTeacher(){try{return JSON.parse(cloudStorage.getItem(teacherKey)||'null')}catch{return null}}
async function cloudRequest(path,body,token){
  if(!cloudConfig.url||!cloudConfig.key)throw Error('云端后台尚未连接，请稍后再试。');
  const res=await fetch(cloudConfig.url+path,{method:'POST',headers:{'Content-Type':'application/json',apikey:cloudConfig.key,...(token?{Authorization:'Bearer '+token}:{})},body:JSON.stringify(body),signal:AbortSignal.timeout(20000)});
  const value=await res.json();
  if(!res.ok||value?.error){const error=Error(value?.error_description||value?.msg||(typeof value?.error==='string'?value.error:null)||value?.message||'连接失败，请稍后重试。');error.status=value?.status||res.status;throw error}
  return value;
}
let refreshTeacher;
async function teacherToken(){
  let auth=savedTeacher();if(!auth)return null;
  if(auth.expires_at>Date.now()/1000+60)return auth.access_token;
  refreshTeacher ||= cloudRequest('/auth/v1/token?grant_type=refresh_token',{refresh_token:auth.refresh_token}).then(value=>{value.expires_at=Date.now()/1000+value.expires_in;cloudStorage.setItem(teacherKey,JSON.stringify(value));return value.access_token}).catch(error=>{cloudStorage.removeItem(teacherKey);throw error}).finally(()=>{refreshTeacher=null});
  return refreshTeacher;
}
window.islandCloud={
  async request(path,options={}){
    const url=new URL(path,location.origin),student=url.pathname.startsWith('/api/student/');
    const value=await cloudRequest('/rest/v1/rpc/island_api',{p_path:url.pathname,p_method:options.method||'GET',p_body:options.body?JSON.parse(options.body):{},p_student_token:student?cloudStorage.getItem(studentKey):null,p_profile:url.searchParams.get('profile')},student?null:await teacherToken());
    if(url.pathname==='/api/student/login')cloudStorage.setItem(studentKey,value.token);
    if(url.pathname==='/api/student/logout')cloudStorage.removeItem(studentKey);
    return value;
  },
  async signIn(email,password){
    const value=await cloudRequest('/auth/v1/token?grant_type=password',{email,password});
    value.expires_at=Date.now()/1000+value.expires_in;cloudStorage.setItem(teacherKey,JSON.stringify(value));
    try{await this.request('/api/session')}catch(error){cloudStorage.removeItem(teacherKey);throw error}
  },
  async signOut(){const auth=savedTeacher();cloudStorage.removeItem(teacherKey);if(auth)try{await cloudRequest('/auth/v1/logout',{},auth.access_token)}catch{}},
};
