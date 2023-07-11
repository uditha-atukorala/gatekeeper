#pragma once

#include <set>
#include <string>
#include <vector>

#include "pg.h"
#include "policies.h"

namespace datastore {
class RbacPolicy {
public:
	using collection_t  = std::string;
	using collections_t = std::set<collection_t>;
	using identity_t    = std::string;
	using identities_t  = std::set<identity_t>;

	struct Rule {
		using attrs_t = std::optional<std::string>;

		const attrs_t     attrs;
		const std::string roleId;

		bool operator<(const Rule &rhs) const noexcept { return roleId < rhs.roleId; }
		bool operator==(const Rule &) const noexcept = default;
	};

	struct Cache {
		const std::string identity;
		const std::string permission;
		const std::string policy;
		const Rule        rule;

		static const Policies check(const std::string &identity, const std::string &permission);

		static const std::string key(const std::string &identity, const std::string &permission) {
			return "rbac:(" + identity + ")›[" + permission + "]";
		}

		const std::string key() const noexcept { return key(identity, permission); };

		void discard() const;
		void store() const;
	};

	struct Data {
		using name_t = std::optional<std::string>;

		std::string id;
		name_t      name;

		bool operator==(const Data &) const noexcept = default;
	};

	using Rules = std::vector<Rule>;

	RbacPolicy(const Data &data) noexcept;
	RbacPolicy(Data &&data) noexcept;

	RbacPolicy(const pg::row_t &t);

	const std::string &id() const noexcept { return _data.id; }
	const int         &rev() const noexcept { return _rev; }

	const collections_t collections() const;
	void                addCollection(const collection_t &id) const;

	const identities_t identities(bool expand = false) const;
	void               addIdentity(const identity_t &id) const;

	const Data::name_t &name() const noexcept { return _data.name; }
	void                name(const std::string &name) noexcept { _data.name = name; }
	void                name(std::string &&name) noexcept { _data.name = std::move(name); }

	const Rules rules() const;
	void        addRule(const Rule &rule) const;

	void store() const;

private:
	Data        _data;
	mutable int _rev;
};

using RbacPolicies = std::vector<RbacPolicy>;

RbacPolicy RetrieveRbacPolicy(const std::string &id);
} // namespace datastore
