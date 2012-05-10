drop table if exists user;
create table user (
	user_id integer primary key autoincrement,
	username string not null,
	email string not null,
	pw_hash string not null
);

drop table if exists entry;
create table entry (
	entry_id integer primary key autoincrement,
	sheet_id integer not null,
	start_time time not null,
	end_time time not null
);

drop table if exists timesheet;
create table timesheet (
	sheet_id integer primary key autoincrement,
	author_id integer not null,
	project_name string,
	pub_date date not null
	
);