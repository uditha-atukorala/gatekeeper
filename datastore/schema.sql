create table if not exists collections (
	_id  text    not null,
	_rev integer not null,
	name text    not null,

	constraint "collections.pkey" primary key (_id)
);

create table if not exists identities (
	_id  text    not null,
	_rev integer not null,
	sub  text    not null,

	constraint "identities.pkey" primary key (_id),
	constraint "identities.key-sub" unique (sub)
);

create table if not exists collection_members (
	collection_id text,
	identity_id   text,

	constraint "collection_members.pkey" primary key (collection_id, identity_id),
	constraint "collection_members.fkey-collection_id" foreign key (collection_id)
		references collections(_id)
		on delete cascade,
	constraint "collection_members.fkey-identity_id" foreign key (identity_id)
		references identities(_id)
		on delete cascade
);