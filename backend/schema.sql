-- Run once in the Supabase SQL editor. No keys or student data belong in this file.
begin;
create extension if not exists pgcrypto with schema extensions;
create schema if not exists island_private;
revoke all on schema island_private from public, anon, authenticated;
create table if not exists island_private.teachers (user_id uuid primary key references auth.users(id));
create table if not exists island_private.profiles (id uuid primary key default gen_random_uuid(), name text not null check(length(name) between 1 and 24), created_at timestamptz not null default now());
create table if not exists island_private.lessons (date date primary key, topic text not null, words jsonb not null, updated_at timestamptz not null default now());
create table if not exists island_private.progress (profile_id uuid primary key references island_private.profiles(id), data jsonb not null, updated_at timestamptz not null default now());
create table if not exists island_private.codes (profile_id uuid primary key references island_private.profiles(id), code_hash text unique not null, created_at timestamptz not null default now());
create table if not exists island_private.sessions (token_hash text primary key, profile_id uuid not null references island_private.profiles(id), code_hash text not null, expires_at timestamptz not null);
create table if not exists island_private.login_limits (bucket text primary key, attempts integer not null, expires_at timestamptz not null);
alter table island_private.teachers enable row level security;
alter table island_private.profiles enable row level security;
alter table island_private.lessons enable row level security;
alter table island_private.progress enable row level security;
alter table island_private.codes enable row level security;
alter table island_private.sessions enable row level security;
alter table island_private.login_limits enable row level security;
revoke all on all tables in schema island_private from public, anon, authenticated;

create or replace function public.island_api(
  p_path text,
  p_method text default 'GET',
  p_body jsonb default '{}'::jsonb,
  p_student_token text default null,
  p_profile text default null
) returns jsonb language plpgsql security definer set search_path = '' as $$
declare
  v_profile island_private.profiles%rowtype;
  v_token text; v_code text; v_hash text; v_bucket text; v_attempts integer;
  v_teacher boolean; v_lessons jsonb; v_result jsonb; v_word jsonb; v_seen text[] := '{}';
  v_date date; v_id uuid; v_updated timestamptz; v_expected timestamptz;
  v_today date := (now() at time zone 'Asia/Hong_Kong')::date;
  v_headers jsonb := coalesce(nullif(current_setting('request.headers',true),''),'{}')::jsonb;
begin
  if length(p_path)>100 or p_method not in ('GET','POST','PUT','DELETE') or octet_length(p_body::text)>1500000 then
    return jsonb_build_object('error','请求内容无效','status',400);
  end if;
  if p_path='/api/student/login' and p_method='POST' then
    v_bucket:=encode(extensions.digest(coalesce(v_headers->>'x-forwarded-for',v_headers->>'cf-connecting-ip','unknown')||':'||floor(extract(epoch from now())/900)::text,'sha256'),'hex');
    delete from island_private.login_limits where expires_at<now();
    insert into island_private.login_limits values(v_bucket,1,now()+interval '15 minutes')
      on conflict(bucket) do update set attempts=island_private.login_limits.attempts+1 returning attempts into v_attempts;
    if v_attempts>30 then return jsonb_build_object('error','尝试次数过多，请 15 分钟后再试。','status',429); end if;
    v_code:=lower(regexp_replace(coalesce(p_body->>'code',''),'[\s-]','','g'));
    if v_code !~ '^[a-f0-9]{24}$' then return jsonb_build_object('error','学习码不正确或已重置，请向老师确认。','status',401); end if;
    v_hash:=encode(extensions.digest(v_code,'sha256'),'hex');
    select p.* into v_profile from island_private.profiles p join island_private.codes c on c.profile_id=p.id where c.code_hash=v_hash;
    if v_profile.id is null then return jsonb_build_object('error','学习码不正确或已重置，请向老师确认。','status',401); end if;
    v_token:=encode(extensions.gen_random_bytes(32),'hex');
    delete from island_private.sessions where expires_at<now();
    insert into island_private.sessions values(encode(extensions.digest(v_token,'sha256'),'hex'),v_profile.id,v_hash,now()+interval '7 days');
    delete from island_private.login_limits where bucket=v_bucket;
    return jsonb_build_object('ok',true,'token',v_token);
  end if;
  if p_path like '/api/student/%' then
    if p_student_token is not null and p_student_token ~ '^[a-f0-9]{64}$' then
      select p.* into v_profile from island_private.sessions s
        join island_private.codes c on c.profile_id=s.profile_id and c.code_hash=s.code_hash
        join island_private.profiles p on p.id=s.profile_id
        where s.token_hash=encode(extensions.digest(p_student_token,'sha256'),'hex') and s.expires_at>now();
    end if;
    if p_path='/api/student/logout' and p_method='POST' then
      delete from island_private.sessions where token_hash=encode(extensions.digest(coalesce(p_student_token,''),'sha256'),'hex');
      return jsonb_build_object('ok',true);
    end if;
    if v_profile.id is null then return jsonb_build_object('error','请先输入老师给你的学习码。','status',401); end if;
    if p_path='/api/student/session' and p_method='GET' then
      select coalesce(jsonb_agg(to_jsonb(l) order by l.date desc),'[]') into v_lessons from
        (select * from island_private.lessons where date<=v_today order by date desc limit 120) l;
      return jsonb_build_object('admin',false,'student',true,'profiles',jsonb_build_array(jsonb_build_object('id',v_profile.id,'name',v_profile.name)),'lessons',v_lessons);
    end if;
    if p_profile is not null and p_profile<>v_profile.id::text then return jsonb_build_object('error','只能访问自己的学习档案','status',403); end if;
    if p_path='/api/student/progress' then v_id:=v_profile.id; end if;
  else
    select exists(select 1 from island_private.teachers t join auth.users u on u.id=t.user_id where t.user_id=auth.uid() and u.email_confirmed_at is not null) into v_teacher;
    if not v_teacher then return jsonb_build_object('error','请使用已授权的老师账户登录。','status',403); end if;
    if p_path='/api/session' and p_method='GET' then
      select coalesce(jsonb_agg(to_jsonb(l) order by l.date desc),'[]') into v_lessons from (select * from island_private.lessons order by date desc limit 120) l;
      select coalesce(jsonb_agg(jsonb_build_object('id',p.id,'name',p.name,'code_created',c.created_at) order by p.created_at),'[]') into v_result from island_private.profiles p left join island_private.codes c on c.profile_id=p.id;
      return jsonb_build_object('admin',true,'profiles',v_result,'lessons',v_lessons);
    end if;
    if p_path='/api/profiles' and p_method='POST' then
      if length(trim(coalesce(p_body->>'name',''))) not between 1 and 24 then return jsonb_build_object('error','请填写 1–24 字的学生昵称','status',400); end if;
      insert into island_private.profiles(name) values(trim(p_body->>'name')) returning * into v_profile;
      return jsonb_build_object('id',v_profile.id,'name',v_profile.name);
    end if;
    if p_path='/api/profiles' and p_method='DELETE' then
      select * into v_profile from island_private.profiles where id::text=p_body->>'id' for update;
      if v_profile.id is null then return jsonb_build_object('error','学生档案不存在或已删除','status',404); end if;
      if p_body->>'name' is distinct from v_profile.name then return jsonb_build_object('error','请输入完整的学生昵称以确认删除','status',400); end if;
      delete from island_private.sessions where profile_id=v_profile.id;
      delete from island_private.codes where profile_id=v_profile.id;
      delete from island_private.progress where profile_id=v_profile.id;
      delete from island_private.profiles where id=v_profile.id;
      return jsonb_build_object('ok',true);
    end if;
    if p_path='/api/admin/code' and p_method='POST' then
      select * into v_profile from island_private.profiles where id::text=p_body->>'profile';
      if v_profile.id is null then return jsonb_build_object('error','学生档案不存在','status',404); end if;
      v_code:=encode(extensions.gen_random_bytes(12),'hex');
      delete from island_private.sessions where profile_id=v_profile.id;
      insert into island_private.codes values(v_profile.id,encode(extensions.digest(v_code,'sha256'),'hex'),now())
        on conflict(profile_id) do update set code_hash=excluded.code_hash,created_at=excluded.created_at;
      return jsonb_build_object('code',upper(concat_ws('-',substr(v_code,1,4),substr(v_code,5,4),substr(v_code,9,4),substr(v_code,13,4),substr(v_code,17,4),substr(v_code,21,4))),'profile',v_profile.id);
    end if;
    if p_path='/api/admin/students' and p_method='GET' then
      select coalesce(jsonb_agg(to_jsonb(s)),'[]') into v_result from
        (select p.id,p.name,c.created_at as code_created,g.data,g.updated_at from island_private.profiles p
        left join island_private.codes c on c.profile_id=p.id left join island_private.progress g on g.profile_id=p.id order by g.updated_at desc nulls last limit 200) s;
      return v_result;
    end if;
    if p_path='/api/admin/lesson' and p_method='PUT' then
      if coalesce(p_body->>'date','') !~ '^\d{4}-\d{2}-\d{2}$' or jsonb_typeof(p_body->'words') is distinct from 'array' then return jsonb_build_object('error','请选择日期并提供词表','status',400); end if;
      begin v_date:=(p_body->>'date')::date; exception when others then return jsonb_build_object('error','日期无效','status',400); end;
      if jsonb_array_length(p_body->'words') not between 10 and 120 or octet_length(p_body::text)>250000 then return jsonb_build_object('error','每天需要 10–120 个词目，词表内容不能过长','status',400); end if;
      if length(trim(coalesce(p_body->>'topic',''))) not between 1 and 60 then return jsonb_build_object('error','请填写 1–60 字的词表主题','status',400); end if;
      for v_word in select value from jsonb_array_elements(p_body->'words') loop
        if jsonb_typeof(v_word) is distinct from 'object' or exists(select 1 from unnest(array['w','m','pos','topic','chunk','e','e2','hint']) k where jsonb_typeof(v_word->k) is distinct from 'string' or length(trim(v_word->>k))=0 or length(v_word->>k)>1000) then return jsonb_build_object('error','词条需要完整填写','status',400); end if;
        if lower(v_word->>'w')=any(v_seen) or position(lower(v_word->>'w') in lower(v_word->>'e'))=0 or position(lower(v_word->>'w') in lower(v_word->>'e2'))=0 then return jsonb_build_object('error','单词不能重复，两条例句都需包含所学单词','status',400); end if;
        v_seen:=array_append(v_seen,lower(v_word->>'w'));
      end loop;
      perform pg_advisory_xact_lock(hashtext('island-lesson:'||v_date::text));
      select updated_at into v_updated from island_private.lessons where date=v_date;
      if p_body ? 'expected_updated_at' then
        begin v_expected:=(p_body->>'expected_updated_at')::timestamptz; exception when others then return jsonb_build_object('error','词表版本无效，请重新载入','status',400); end;
        if v_updated is distinct from v_expected then return jsonb_build_object('error','这一天的词表已在其他页面更新，请重新载入后再发布。','status',409); end if;
      end if;
      insert into island_private.lessons values(v_date,trim(p_body->>'topic'),p_body->'words',clock_timestamp())
        on conflict(date) do update set topic=excluded.topic,words=excluded.words,updated_at=excluded.updated_at;
      return jsonb_build_object('ok',true);
    end if;
    if p_path='/api/progress' then select id into v_id from island_private.profiles where id::text=p_profile; end if;
  end if;
  if p_path in ('/api/progress','/api/student/progress') then
    if v_id is null then return jsonb_build_object('error','学生档案不存在','status',404); end if;
    if p_method='GET' then select data into v_result from island_private.progress where profile_id=v_id; return v_result; end if;
    if p_method='PUT' then
      if jsonb_typeof(p_body) is distinct from 'object' or jsonb_typeof(p_body->'days') is distinct from 'object' or jsonb_typeof(p_body->'records') is distinct from 'object' or jsonb_typeof(p_body->'stars') is distinct from 'number' or (p_body->>'stars')::numeric<0 then return jsonb_build_object('error','学习记录格式不正确','status',400); end if;
      insert into island_private.progress values(v_id,p_body,now()) on conflict(profile_id) do update set data=excluded.data,updated_at=excluded.updated_at;
      return jsonb_build_object('ok',true);
    end if;
  end if;
  return jsonb_build_object('error','未找到此功能','status',404);
end;
$$;
revoke all on function public.island_api(text,text,jsonb,text,text) from public;
grant execute on function public.island_api(text,text,jsonb,text,text) to anon,authenticated;
commit;
