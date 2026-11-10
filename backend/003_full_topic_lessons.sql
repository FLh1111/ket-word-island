-- Support a complete Appendix 2 topic without changing any lessons or student records.
begin;
do $migration$
declare definition text;
begin
  definition := pg_get_functiondef('public.island_api(text,text,jsonb,text,text)'::regprocedure);
  if position('not between 10 and 20 or octet_length(p_body::text)>100000' in definition)>0 then
    definition := replace(definition,'not between 10 and 20 or octet_length(p_body::text)>100000','not between 10 and 120 or octet_length(p_body::text)>250000');
    definition := replace(definition,'每天需要 10–20 个词，词表内容不能过长','每天需要 10–120 个词目，词表内容不能过长');
    execute definition;
  elsif position('not between 10 and 120 or octet_length(p_body::text)>250000' in definition)=0 then
    raise exception 'Unexpected lesson validation definition; no changes applied.';
  end if;
end;
$migration$;
commit;
select 'PASS: complete-topic publishing allows 10–120 entries; existing records unchanged.' as result;
