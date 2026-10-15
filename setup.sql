-- CatchApp pilot database. Paste this whole file into Supabase: SQL Editor > New query > Run.
-- Safe to run once on a fresh project.

-- ---------- tables ----------
create table invites (
  code text primary key,
  uses_left int not null default 25
);

create table profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  name text not null check (char_length(name) between 1 and 24),
  city text not null default '' check (char_length(city) <= 40),
  bio text not null default '' check (char_length(bio) <= 80),
  banned boolean not null default false,
  created_at timestamptz not null default now()
);

create table posts (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references profiles(id) on delete cascade,
  sport text not null check (sport in ('baseball','football','basketball','soccer')),
  spot text not null check (char_length(spot) between 1 and 80),
  starts_at timestamptz not null,
  dur int not null check (dur between 5 and 180),
  created_at timestamptz not null default now()
);

create table live (
  user_id uuid primary key references profiles(id) on delete cascade,
  sport text not null check (sport in ('baseball','football','basketball','soccer')),
  spot text not null check (char_length(spot) between 1 and 80),
  until timestamptz not null,
  created_at timestamptz not null default now()
);

create table requests (
  id uuid primary key default gen_random_uuid(),
  from_id uuid not null references profiles(id) on delete cascade,
  to_id uuid not null references profiles(id) on delete cascade,
  post_id uuid references posts(id) on delete set null,
  live boolean not null default false,
  sport text not null check (sport in ('baseball','football','basketball','soccer')),
  spot text not null check (char_length(spot) between 1 and 80),
  starts_at timestamptz,
  dur int not null default 30,
  status text not null default 'pending' check (status in ('pending','accepted','declined','cancelled')),
  created_at timestamptz not null default now(),
  check (from_id <> to_id)
);
create unique index requests_one_per_post on requests(from_id, post_id) where post_id is not null;
create unique index requests_one_live_ping on requests(from_id, to_id) where live and status = 'pending';

create table ratings (
  id uuid primary key default gen_random_uuid(),
  request_id uuid not null references requests(id) on delete cascade,
  rater_id uuid not null references profiles(id) on delete cascade,
  ratee_id uuid not null references profiles(id) on delete cascade,
  stars int not null check (stars between 1 and 5),
  safe boolean not null default true,
  tags text[] not null default '{}',
  created_at timestamptz not null default now(),
  unique (request_id, rater_id)
);

create table blocks (
  blocker_id uuid not null references profiles(id) on delete cascade,
  blocked_id uuid not null references profiles(id) on delete cascade,
  created_at timestamptz not null default now(),
  primary key (blocker_id, blocked_id)
);

create table reports (
  id uuid primary key default gen_random_uuid(),
  reporter_id uuid not null references profiles(id) on delete cascade,
  reported_id uuid not null references profiles(id) on delete cascade,
  request_id uuid references requests(id) on delete set null,
  reason text not null default 'report',
  created_at timestamptz not null default now()
);

-- ---------- helpers ----------
create function is_member() returns boolean
language sql stable security definer set search_path = public as $$
  select exists (select 1 from profiles where id = auth.uid() and not banned);
$$;

-- Joining requires a valid invite code. This is the only way to create a profile.
create function claim_invite(p_code text, p_name text, p_city text) returns void
language plpgsql security definer set search_path = public as $$
declare n int;
begin
  if auth.uid() is null then raise exception 'not signed in'; end if;
  if exists (select 1 from profiles where id = auth.uid() and banned) then raise exception 'account suspended'; end if;
  if exists (select 1 from profiles where id = auth.uid()) then return; end if;
  update invites set uses_left = uses_left - 1 where lower(code) = lower(trim(p_code)) and uses_left > 0;
  get diagnostics n = row_count;
  if n = 0 then raise exception 'invalid invite'; end if;
  insert into profiles (id, name, city) values (auth.uid(), left(trim(p_name), 24), left(coalesce(trim(p_city), ''), 40));
end $$;
revoke all on function claim_invite(text, text, text) from public, anon;
grant execute on function claim_invite(text, text, text) to authenticated;
revoke all on function is_member() from public, anon;
grant execute on function is_member() to authenticated;

-- Name, city, bio and average rating, visible to members only.
create view people as
  select p.id, p.name, p.city, p.bio, s.avg_stars, coalesce(s.n, 0) as n
  from profiles p
  left join (select ratee_id, round(avg(stars), 1) as avg_stars, count(*) as n from ratings group by ratee_id) s on s.ratee_id = p.id
  where is_member() and not p.banned;
revoke all on people from public, anon;
grant select on people to authenticated;

-- ---------- row level security ----------
alter table invites enable row level security;      -- no policies: nobody can read codes
alter table profiles enable row level security;
alter table posts enable row level security;
alter table live enable row level security;
alter table requests enable row level security;
alter table ratings enable row level security;
alter table blocks enable row level security;
alter table reports enable row level security;

revoke all on invites from anon, authenticated;
revoke insert, update, delete on profiles from anon, authenticated;
grant update (name, city, bio) on profiles to authenticated;

create policy "own profile" on profiles for select to authenticated using (id = auth.uid());
create policy "edit own profile" on profiles for update to authenticated using (id = auth.uid() and is_member()) with check (id = auth.uid());

create policy "members read posts" on posts for select to authenticated using (is_member());
create policy "members add own posts" on posts for insert to authenticated with check (user_id = auth.uid() and is_member());
create policy "delete own posts" on posts for delete to authenticated using (user_id = auth.uid());

create policy "members read live" on live for select to authenticated using (is_member());
create policy "go live" on live for insert to authenticated with check (user_id = auth.uid() and is_member());
create policy "update own live" on live for update to authenticated using (user_id = auth.uid()) with check (user_id = auth.uid());
create policy "stop live" on live for delete to authenticated using (user_id = auth.uid());

create policy "see own requests" on requests for select to authenticated using (is_member() and (from_id = auth.uid() or to_id = auth.uid()));
create policy "send request" on requests for insert to authenticated with check (
  from_id = auth.uid() and status = 'pending' and is_member()
  and not exists (select 1 from blocks b where b.blocker_id = to_id and b.blocked_id = auth.uid())
);
create policy "recipient answers" on requests for update to authenticated
  using (to_id = auth.uid() and status in ('pending','accepted'))
  with check (to_id = auth.uid() and status in ('accepted','declined','cancelled'));
create policy "sender cancels" on requests for update to authenticated
  using (from_id = auth.uid() and status in ('pending','accepted'))
  with check (from_id = auth.uid() and status = 'cancelled');

create policy "see my ratings" on ratings for select to authenticated using (is_member() and (rater_id = auth.uid() or ratee_id = auth.uid()));
create policy "rate after a catch" on ratings for insert to authenticated with check (
  rater_id = auth.uid() and is_member()
  and exists (select 1 from requests r where r.id = request_id and r.status = 'accepted'
    and ((r.from_id = auth.uid() and r.to_id = ratee_id) or (r.to_id = auth.uid() and r.from_id = ratee_id)))
);

create policy "see my blocks" on blocks for select to authenticated using (blocker_id = auth.uid());
create policy "block someone" on blocks for insert to authenticated with check (blocker_id = auth.uid() and is_member());

create policy "file a report" on reports for insert to authenticated with check (reporter_id = auth.uid() and is_member());

-- ---------- live updates ----------
alter publication supabase_realtime add table posts, live, requests, ratings;

-- ---------- your first invite code (change the word, keep it hard to guess) ----------
insert into invites (code, uses_left) values ('CATCH-PILOT', 25);
