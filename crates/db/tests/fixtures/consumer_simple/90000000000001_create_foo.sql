-- Simple consumer migration: no FK to rust-saas tables.
create table foo (id int primary key, name text not null);
