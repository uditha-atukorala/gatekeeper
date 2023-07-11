#include "rbac-policies.h"

#include <utility>

#include <xid/xid.h>

#include "err/errors.h"

#include "collections.h"
#include "redis.h"
#include "roles.h"

namespace datastore {
RbacPolicy::RbacPolicy(const RbacPolicy::Data &data) noexcept : _data(data), _rev(0) {
	if (_data.id.empty()) {
		_data.id = xid::next();
	}
}

RbacPolicy::RbacPolicy(Data &&data) noexcept : _data(std::move(data)), _rev(0) {
	if (_data.id.empty()) {
		_data.id = xid::next();
	}
}

RbacPolicy::RbacPolicy(const pg::row_t &r) :
	_data({
		.id   = r["_id"].as<std::string>(),
		.name = r["name"].as<std::string>(),
	}),
	_rev(r["_rev"].as<int>()) {}

void RbacPolicy::addCollection(const collection_t &id) const {
	std::string_view qry = R"(
		insert into "rbac-policies_collections" (
			policy_id,
			collection_id
		) values (
			$1::text,
			$2::text
		);
	)";

	try {
		pg::exec(qry, _data.id, id);
	} catch (pg::fkey_violation_t &) {
		throw err::DatastoreInvalidRbacPolicyOrPrincipal();
	} catch (pg::unique_violation_t &) {
		throw err::DatastoreDuplicateRbacPolicyPrincipal();
	}

	const auto members = RetrieveCollectionMembers(id);
	for (const auto &mid : members) {
		for (const auto &rule : rules()) {
			const auto role = RetrieveRole(rule.roleId);
			for (const auto &perm : role.permissions()) {
				Cache cache({
					.identity   = mid,
					.permission = perm,
					.policy     = _data.id,
					.rule       = rule,
				});

				cache.store();
			}
		}
	}
}

void RbacPolicy::addIdentity(const identity_t &id) const {
	std::string_view qry = R"(
		insert into "rbac-policies_identities" (
			policy_id,
			identity_id
		) values (
			$1::text,
			$2::text
		);
	)";

	try {
		pg::exec(qry, _data.id, id);
	} catch (pg::fkey_violation_t &) {
		throw err::DatastoreInvalidRbacPolicyOrPrincipal();
	} catch (pg::unique_violation_t &) {
		throw err::DatastoreDuplicateRbacPolicyPrincipal();
	}

	for (const auto &rule : rules()) {
		const auto role = RetrieveRole(rule.roleId);
		for (const auto &perm : role.permissions()) {
			Cache cache({
				.identity   = id,
				.permission = perm,
				.policy     = _data.id,
				.rule       = rule,
			});

			cache.store();
		}
	}
}

void RbacPolicy::addRule(const Rule &rule) const {
	std::string_view qry = R"(
		insert into "rbac-policies_roles" (
			policy_id,
			role_id,
			attrs
		) values (
			$1::text,
			$2::text,
			$3::jsonb
		);
	)";

	try {
		pg::exec(qry, _data.id, rule.roleId, rule.attrs);
	} catch (pg::fkey_violation_t &) {
		throw err::DatastoreInvalidRbacPolicyOrRole();
	} catch (pg::unique_violation_t &) {
		throw err::DatastoreDuplicateRbacPolicyRole();
	}
}

const RbacPolicy::collections_t RbacPolicy::collections() const {
	std::string_view qry = R"(
		select
			collection_id
		from "rbac-policies_collections"
		where policy_id = $1::text;
	)";

	auto res = pg::exec(qry, _data.id);

	RbacPolicy::collections_t collections;
	for (const auto &r : res) {
		collections.insert(r["collection_id"].as<collection_t>());
	}

	return collections;
}

const RbacPolicy::identities_t RbacPolicy::identities(bool expand) const {
	std::string qry = R"(
		select
			identity_id
		from "rbac-policies_identities"
		where policy_id = $1::text
	)";

	if (expand) {
		qry += R"(
			union
			select
				c.identity_id
			from
				"rbac-policies_collections" p
				join "collections_identities" c on p.collection_id = c.collection_id
			;
		)";
	} else {
		qry += ';';
	}

	auto res = pg::exec(qry, _data.id);

	RbacPolicy::identities_t identities;
	for (const auto &r : res) {
		identities.insert(r["identity_id"].as<identity_t>());
	}

	return identities;
}

const RbacPolicy::Rules RbacPolicy::rules() const {
	std::string_view qry = R"(
		select
			attrs,
			role_id
		from "rbac-policies_roles"
		where
			policy_id = $1::text;
	)";

	auto res = pg::exec(qry, id());

	Rules rules;
	for (const auto &r : res) {
		rules.push_back(Rule({
			.attrs  = r["attrs"].as<Rule::attrs_t>(),
			.roleId = r["role_id"].as<std::string>(),
		}));
	}

	return rules;
}

void RbacPolicy::store() const {
	std::string_view qry = R"(
		insert into "rbac-policies" as t (
			_id,
			_rev,
			name
		) values (
			$1::text,
			$2::integer,
			$3::text
		)
		on conflict (_id)
		do update
			set (
				_rev,
				name
			) = (
				excluded._rev + 1,
				$3::text
			)
			where t._rev = $2::integer
		returning _rev;
	)";

	auto res = pg::exec(qry, _data.id, _rev, _data.name);
	if (res.empty()) {
		throw err::DatastoreRevisionMismatch();
	}

	_rev = res.at(0, 0).as<int>();
}

const Policies RbacPolicy::Cache::check(
	const std::string &identity, const std::string &permission) {
	auto conn  = datastore::redis::conn();
	auto reply = conn.cmd("hgetall %s", key(identity, permission).c_str());

	Policies policies;
	for (int i = 0; i < reply->elements; i += 2) {
		policies.push_back({
			.attrs = reply->element[i + 1]->str,
			.id    = reply->element[i]->str,
		});
	}

	return policies;
}

void RbacPolicy::Cache::discard() const {
	datastore::redis::conn().cmd("del %s", key().c_str());
}

void RbacPolicy::Cache::store() const {
	auto conn = datastore::redis::conn();
	conn.cmd("hset %s %s %s", key().c_str(), policy.c_str(), rule.attrs.value_or("").c_str());
}

RbacPolicy RetrieveRbacPolicy(const std::string &id) {
	std::string_view qry = R"(
		select
			_id,
			_rev,
			name
		from "rbac-policies"
		where
			_id = $1::text;
	)";

	auto res = pg::exec(qry, id);
	if (res.empty()) {
		throw err::DatastoreRbacPolicyNotFound();
	}

	return RbacPolicy(res[0]);
}
} // namespace datastore
