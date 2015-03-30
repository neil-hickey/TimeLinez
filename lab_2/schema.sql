drop table if exists user;
create table user (
  user_id integer primary key autoincrement,
  username text not null,
  email text not null,
  pw_hash text not null
);

drop table if exists message;
create table message (
  message_id integer primary key autoincrement,
  author_id integer not null,
  text text not null,
  pub_date integer
);

drop table if exists _group;
create table _group (
  group_id integer primary key autoincrement,
  shared_key text not null,
  owner_id integer,
  name text
);

drop table if exists _member;
create table _member (
  member_id integer,
  group_id integer
);