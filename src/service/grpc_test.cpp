#include <grpcpp/test/default_reactor_test_peer.h>
#include <gtest/gtest.h>

#include "datastore/access-policies.h"
#include "datastore/collections.h"
#include "datastore/identities.h"
#include "datastore/rbac-policies.h"
#include "datastore/roles.h"
#include "datastore/testing.h"

#include "grpc.h"

class GrpcTest : public ::testing::Test {
protected:
	static void SetUpTestSuite() {
		datastore::testing::setup();

		// Clear data
		datastore::pg::exec("truncate table \"access-policies\" cascade;");
		datastore::pg::exec("truncate table collections cascade;");
		datastore::pg::exec("truncate table identities cascade;");
		datastore::redis::conn().cmd("flushall");
	}

	void SetUp() {
		// Clear data before each test
		datastore::pg::exec("delete from \"access-policies\" cascade;");
		datastore::pg::exec("delete from collections cascade;");
		datastore::pg::exec("delete from identities cascade;");
		datastore::pg::exec("delete from \"rbac-policies\" cascade;");
	}

	static void TearDownTestSuite() { datastore::testing::teardown(); }
};

// Access control checks
TEST_F(GrpcTest, CheckAccess) {
	service::Grpc service;

	// Success: returns policy when found
	{
		grpc::CallbackServerContext           ctx;
		grpc::testing::DefaultReactorTestPeer peer(&ctx);
		gk::v1::CheckAccessResponse           response;

		const datastore::Identity identity({
			.sub = "sub:GrpcTest.CheckAccess",
		});
		ASSERT_NO_THROW(identity.store());

		const datastore::AccessPolicy policy({
			.name = "name:GrpcTest.CheckAccess",
		});
		ASSERT_NO_THROW(policy.store());

		const std::string resource = "resource/GrpcTest.CheckAccess";

		const datastore::AccessPolicy::Cache cache({
			.identity = identity.id(),
			.policy   = policy.id(),
			.rule     = {.resource = resource},
		});
		ASSERT_NO_THROW(cache.store());

		gk::v1::CheckAccessRequest request;
		request.set_resource(resource);
		request.set_identity_id(identity.id());

		auto reactor = service.CheckAccess(&ctx, &request, &response);
		EXPECT_TRUE(peer.test_status_set());
		EXPECT_TRUE(peer.test_status().ok());
		EXPECT_EQ(peer.reactor(), reactor);
		EXPECT_EQ(1, response.policies().size());
	}
}

TEST_F(GrpcTest, CheckRbac) {
	service::Grpc service;

	// Success: returns policy when found
	{
		grpc::CallbackServerContext           ctx;
		grpc::testing::DefaultReactorTestPeer peer(&ctx);
		gk::v1::CheckRbacResponse             response;

		// create identity
		const datastore::Identity identity({.sub = "sub:GrpcTest.CheckRbac"});
		ASSERT_NO_THROW(identity.store());

		datastore::RbacPolicy policy({
			.name = "name::GrpcTest.CheckRbac",
		});
		ASSERT_NO_THROW(policy.store());

		const auto permission = "permission:GrpcTest.CheckRbac";

		const datastore::RbacPolicy::Cache cache({
			.identity   = identity.id(),
			.permission = permission,
			.policy     = policy.id(),
			.rule       = {},
		});
		ASSERT_NO_THROW(cache.store());

		gk::v1::CheckRbacRequest request;
		request.set_permission(permission);
		request.set_identity_id(identity.id());

		auto reactor = service.CheckRbac(&ctx, &request, &response);
		EXPECT_TRUE(peer.test_status_set());
		EXPECT_TRUE(peer.test_status().ok());
		EXPECT_EQ(peer.reactor(), reactor);
		EXPECT_EQ(1, response.policies().size());
	}
}

// Access Policies
TEST_F(GrpcTest, CreateAccessPolicy) {
	service::Grpc service;

	// Success: create access policy
	{
		grpc::CallbackServerContext           ctx;
		grpc::testing::DefaultReactorTestPeer peer(&ctx);
		gk::v1::AccessPolicy                  response;

		gk::v1::CreateAccessPolicyRequest request;
		request.set_name("name:GrpcTest.CreateAccessPolicy");

		auto reactor = service.CreateAccessPolicy(&ctx, &request, &response);
		EXPECT_TRUE(peer.test_status_set());
		EXPECT_TRUE(peer.test_status().ok());
		EXPECT_EQ(peer.reactor(), reactor);
		EXPECT_EQ(request.name(), response.name());
		EXPECT_FALSE(response.id().empty());
	}

	// Success: create access policy with `id`
	{
		grpc::CallbackServerContext           ctx;
		grpc::testing::DefaultReactorTestPeer peer(&ctx);
		gk::v1::AccessPolicy                  response;

		gk::v1::CreateAccessPolicyRequest request;
		request.set_id("id:GrpcTest.CreateAccessPolicy");
		request.set_name("name:GrpcTest.CreateAccessPolicy");

		auto reactor = service.CreateAccessPolicy(&ctx, &request, &response);
		EXPECT_TRUE(peer.test_status_set());
		EXPECT_TRUE(peer.test_status().ok());
		EXPECT_EQ(peer.reactor(), reactor);
		EXPECT_EQ(request.id(), response.id());
		EXPECT_EQ(request.name(), response.name());
	}

	// Error: duplicate `id`
	{
		const datastore::AccessPolicy policy({.name = "name:GrpcTest.CreateAccessPolicy"});
		EXPECT_NO_THROW(policy.store());

		grpc::CallbackServerContext           ctx;
		grpc::testing::DefaultReactorTestPeer peer(&ctx);
		gk::v1::AccessPolicy                  response;

		gk::v1::CreateAccessPolicyRequest request;
		request.set_id(policy.id());
		request.set_name("name:GrpcTest.CreateAccessPolicy-duplicate");

		auto reactor = service.CreateAccessPolicy(&ctx, &request, &response);
		EXPECT_TRUE(peer.test_status_set());
		EXPECT_EQ(grpc::StatusCode::ALREADY_EXISTS, peer.test_status().error_code());
		EXPECT_EQ("Duplicate policy id", peer.test_status().error_message());
	}

	// Success: create access policy with an identity and resource
	{
		const datastore::Identity identity({
			.sub = "principal_sub:GrpcTest.CreateAccessPolicy",
		});
		ASSERT_NO_THROW(identity.store());

		grpc::CallbackServerContext           ctx;
		grpc::testing::DefaultReactorTestPeer peer(&ctx);
		gk::v1::AccessPolicy                  response;

		gk::v1::CreateAccessPolicyRequest request;
		request.set_name("name:GrpcTest.CreateAccessPolicy");
		request.add_identity_ids(identity.id());

		auto rule = request.add_rules();
		rule->set_resource("resource_id:GrpcTest.CreateAccessPolicy");

		// expect no access before request
		{
			const auto policies =
				datastore::AccessPolicy::Cache::check(identity.id(), rule->resource());
			EXPECT_EQ(0, policies.size());
		}

		// create access policy
		auto reactor = service.CreateAccessPolicy(&ctx, &request, &response);
		EXPECT_TRUE(peer.test_status_set());
		EXPECT_TRUE(peer.test_status().ok());
		EXPECT_EQ(peer.reactor(), reactor);

		// expect to find single policy when checking access
		{
			const auto policies =
				datastore::AccessPolicy::Cache::check(identity.id(), rule->resource());
			EXPECT_EQ(1, policies.size());
		}
	}

	// Success: create an access policy for collection
	// all members of collection should be granted access
	{
		grpc::CallbackServerContext           ctx;
		grpc::testing::DefaultReactorTestPeer peer(&ctx);
		gk::v1::AccessPolicy                  response;

		const datastore::Identity   identity({
			  .id  = "identity_id:GrpcTest.CreateAccessPolicy",
			  .sub = "identity_sub:GrpcTest.CreateAccessPolicy",
        });
		const datastore::Collection collection({
			.id   = "collection_id:GrpcTest.CreateAccessPolicy",
			.name = "collection_name:GrpcTest.CreateAccessPolicy",
		});

		try {
			identity.store();
			collection.store();
			collection.add(identity.id());
		} catch (const std::exception &e) {
			FAIL() << e.what();
		}

		gk::v1::CreateAccessPolicyRequest request;
		request.set_name("name:GrpcTest.CreateAccessPolicy");
		request.add_collection_ids(collection.id());

		auto rule = request.add_rules();
		rule->set_resource("resource_id:GrpcTest.CreateAccessPolicy");

		// expect no access before request
		{
			const auto policies =
				datastore::AccessPolicy::Cache::check(identity.id(), rule->resource());
			EXPECT_EQ(0, policies.size());
		}

		// create access policy
		auto reactor = service.CreateAccessPolicy(&ctx, &request, &response);
		EXPECT_TRUE(peer.test_status_set());
		EXPECT_TRUE(peer.test_status().ok());
		EXPECT_EQ(peer.reactor(), reactor);

		// expect to find single policy when checking access
		{
			const auto policies =
				datastore::AccessPolicy::Cache::check(identity.id(), rule->resource());
			EXPECT_EQ(1, policies.size());
		}
	}

	// FIXME: nested collections
}

// Collections
TEST_F(GrpcTest, CreateCollection) {
	service::Grpc service;

	// Success: create collection
	{
		grpc::CallbackServerContext           ctx;
		grpc::testing::DefaultReactorTestPeer peer(&ctx);
		gk::v1::Collection                    response;

		gk::v1::CreateCollectionRequest request;
		request.set_name("name:GrpcTest.CreateCollection");

		auto reactor = service.CreateCollection(&ctx, &request, &response);
		EXPECT_TRUE(peer.test_status_set());
		EXPECT_TRUE(peer.test_status().ok());
		EXPECT_EQ(peer.reactor(), reactor);
		EXPECT_EQ(request.name(), response.name());
		EXPECT_FALSE(response.id().empty());
	}

	// Success: create collection with `id`
	{
		grpc::CallbackServerContext           ctx;
		grpc::testing::DefaultReactorTestPeer peer(&ctx);
		gk::v1::Collection                    response;

		gk::v1::CreateCollectionRequest request;
		request.set_id("id:GrpcTest.CreateCollection");
		request.set_name("name:GrpcTest.CreateCollection");

		auto reactor = service.CreateCollection(&ctx, &request, &response);
		EXPECT_TRUE(peer.test_status_set());
		EXPECT_TRUE(peer.test_status().ok());
		EXPECT_EQ(peer.reactor(), reactor);
		EXPECT_EQ(request.id(), response.id());
		EXPECT_EQ(request.name(), response.name());
	}

	// Error: duplicate `id`
	{
		const datastore::Collection collection({.name = "name:GrpcTest.CreateCollection"});
		EXPECT_NO_THROW(collection.store());

		grpc::CallbackServerContext           ctx;
		grpc::testing::DefaultReactorTestPeer peer(&ctx);
		gk::v1::Collection                    response;

		gk::v1::CreateCollectionRequest request;
		request.set_id(collection.id());
		request.set_name("name:GrpcTest.CreateCollection-duplicate");

		auto reactor = service.CreateCollection(&ctx, &request, &response);
		EXPECT_TRUE(peer.test_status_set());
		EXPECT_EQ(grpc::StatusCode::ALREADY_EXISTS, peer.test_status().error_code());
		EXPECT_EQ("Duplicate collection id", peer.test_status().error_message());
	}
}

TEST_F(GrpcTest, RetrieveCollection) {
	service::Grpc service;

	// Success: retrieve collection by id
	{
		const datastore::Collection collection(
			{.id = "id:GrpcTest.RetrieveCollection", .name = "name:GrpcTest.RetrieveCollection"});
		EXPECT_NO_THROW(collection.store());

		grpc::CallbackServerContext           ctx;
		grpc::testing::DefaultReactorTestPeer peer(&ctx);
		gk::v1::Collection                    response;

		gk::v1::RetrieveCollectionRequest request;
		request.set_id(collection.id());

		auto reactor = service.RetrieveCollection(&ctx, &request, &response);
		EXPECT_TRUE(peer.test_status_set());
		EXPECT_TRUE(peer.test_status().ok());
		EXPECT_EQ(peer.reactor(), reactor);
		EXPECT_EQ(collection.id(), response.id());
		EXPECT_EQ(collection.name(), response.name());
	}

	// Error: collection not found
	{
		grpc::CallbackServerContext           ctx;
		grpc::testing::DefaultReactorTestPeer peer(&ctx);
		gk::v1::Collection                    response;

		gk::v1::RetrieveCollectionRequest request;
		request.set_id("id:GrpcTest.RetrieveCollection-not-found");

		auto reactor = service.RetrieveCollection(&ctx, &request, &response);
		EXPECT_TRUE(peer.test_status_set());
		EXPECT_EQ(grpc::StatusCode::NOT_FOUND, peer.test_status().error_code());
		EXPECT_EQ("Document not found", peer.test_status().error_message());
	}
}

TEST_F(GrpcTest, UpdateCollection) {
	service::Grpc service;

	// Success: update collection name
	{
		const datastore::Collection collection(
			{.id = "id:GrpcTest.UpdateCollection-name", .name = "name:GrpcTest.UpdateCollection"});
		EXPECT_NO_THROW(collection.store());

		grpc::CallbackServerContext           ctx;
		grpc::testing::DefaultReactorTestPeer peer(&ctx);
		gk::v1::Collection                    response;

		gk::v1::UpdateCollectionRequest request;
		request.set_id(collection.id());
		request.set_name("name:GrpcTest.UpdateCollection-new");

		auto reactor = service.UpdateCollection(&ctx, &request, &response);
		EXPECT_TRUE(peer.test_status_set());
		EXPECT_TRUE(peer.test_status().ok());
		EXPECT_EQ(peer.reactor(), reactor);

		EXPECT_EQ(request.id(), response.id());
		EXPECT_EQ(request.name(), response.name());

		auto updatedCollection = datastore::RetrieveCollection(collection.id());
		EXPECT_EQ(request.name(), updatedCollection.name());
		EXPECT_EQ(1, updatedCollection.rev());
	}

	// Error: no fields to update
	{
		grpc::CallbackServerContext           ctx;
		grpc::testing::DefaultReactorTestPeer peer(&ctx);
		gk::v1::Collection                    response;

		gk::v1::UpdateCollectionRequest request;
		request.set_id("id:GrpcTest.UpdateCollection-no-updates");

		auto reactor = service.UpdateCollection(&ctx, &request, &response);
		EXPECT_TRUE(peer.test_status_set());
		EXPECT_EQ(grpc::StatusCode::INTERNAL, peer.test_status().error_code());
		EXPECT_EQ("No fields to update", peer.test_status().error_message());
	}

	// Error: collection not found
	{
		grpc::CallbackServerContext           ctx;
		grpc::testing::DefaultReactorTestPeer peer(&ctx);
		gk::v1::Collection                    response;

		gk::v1::UpdateCollectionRequest request;
		request.set_id("id:GrpcTest.UpdateCollection-not-found");
		request.set_name("name:GrpcTest.UpdateCollection-not-found");

		auto reactor = service.UpdateCollection(&ctx, &request, &response);
		EXPECT_TRUE(peer.test_status_set());
		EXPECT_EQ(grpc::StatusCode::NOT_FOUND, peer.test_status().error_code());
		EXPECT_EQ("Document not found", peer.test_status().error_message());
	}
}

// Collections - members
TEST_F(GrpcTest, AddCollectionMember) {
	datastore::Collection collection({.name = "name:GrpcTest.AddCollectionMember"});
	ASSERT_NO_THROW(collection.store());

	service::Grpc service;

	// Success: add collection member
	{
		datastore::Identity identity({.sub = "sub:GrpcTest.AddCollectionMember"});
		ASSERT_NO_THROW(identity.store());

		grpc::CallbackServerContext           ctx;
		grpc::testing::DefaultReactorTestPeer peer(&ctx);
		gk::v1::AddCollectionMemberResponse   response;

		gk::v1::AddCollectionMemberRequest request;
		request.set_collection_id(collection.id());
		request.set_identity_id(identity.id());

		auto reactor = service.AddCollectionMember(&ctx, &request, &response);
		EXPECT_TRUE(peer.test_status_set());
		EXPECT_TRUE(peer.test_status().ok());
		EXPECT_EQ(peer.reactor(), reactor);

		{
			std::string_view qry = R"(
					select count(*)
					from collections_identities
					where
						collection_id = $1::text
						and identity_id = $2::text;
				)";

			auto res = datastore::pg::exec(qry, collection.id(), identity.id());
			ASSERT_EQ(1, res.size());

			auto [count] = res[0].as<int>();
			EXPECT_EQ(1, count);
		}
	}
}

TEST_F(GrpcTest, ListCollectionMembers) {
	datastore::Collection collection({.name = "name:GrpcTest.ListCollectionMembers"});
	ASSERT_NO_THROW(collection.store());

	service::Grpc service;

	// Success: list collection members
	{
		std::array<datastore::Identity, 2> identities = {
			datastore::Identity({.sub = "sub:GrpcTest.ListCollectionMembers-1"}),
			datastore::Identity({.sub = "sub:GrpcTest.ListCollectionMembers-2"}),
		};

		for (const auto &idn : identities) {
			ASSERT_NO_THROW(idn.store());
		}

		ASSERT_NO_THROW(collection.add(identities[0].id()));

		grpc::CallbackServerContext           ctx;
		grpc::testing::DefaultReactorTestPeer peer(&ctx);
		gk::v1::ListCollectionMembersResponse response;

		gk::v1::ListCollectionMembersRequest request;
		request.set_id(collection.id());

		auto reactor = service.ListCollectionMembers(&ctx, &request, &response);
		EXPECT_TRUE(peer.test_status_set());
		EXPECT_TRUE(peer.test_status().ok());
		EXPECT_EQ(peer.reactor(), reactor);

		EXPECT_FALSE(response.has_meta());

		ASSERT_EQ(1, response.data_size());
		EXPECT_EQ(identities[0].id(), response.data(0).id());
	}
}

TEST_F(GrpcTest, RemoveCollectionMember) {
	datastore::Collection collection({.name = "name:GrpcTest.RemoveCollectionMember"});
	ASSERT_NO_THROW(collection.store());

	service::Grpc service;

	// Success: remove collection member
	{
		datastore::Identity identity({.sub = "sub:GrpcTest.RemoveCollectionMember"});
		ASSERT_NO_THROW(identity.store());
		ASSERT_NO_THROW(collection.add(identity.id()));

		grpc::CallbackServerContext            ctx;
		grpc::testing::DefaultReactorTestPeer  peer(&ctx);
		gk::v1::RemoveCollectionMemberResponse response;

		gk::v1::RemoveCollectionMemberRequest request;
		request.set_collection_id(collection.id());
		request.set_identity_id(identity.id());

		auto reactor = service.RemoveCollectionMember(&ctx, &request, &response);
		EXPECT_TRUE(peer.test_status_set());
		EXPECT_TRUE(peer.test_status().ok());
		EXPECT_EQ(peer.reactor(), reactor);

		{
			std::string_view qry = R"(
					select count(*)
					from collections_identities
					where
						collection_id = $1::text
						and identity_id = $2::text;
				)";

			auto res = datastore::pg::exec(qry, collection.id(), identity.id());
			ASSERT_EQ(1, res.size());

			auto [count] = res[0].as<int>();
			EXPECT_EQ(0, count);
		}
	}
}

// Events
TEST_F(GrpcTest, ConsumeEvent_cache_rebuild) {
	service::Grpc service;

	// Success: request/cache.rebuild:access
	{
		const datastore::Identity identity({
			.sub = "sub:GrpcTest.ConsumeEvent(request/cache.rebuild:access)",
		});
		ASSERT_NO_THROW(identity.store());

		const datastore::Collection collection({
			.name = "name:GrpcTest.ConsumeEvent(request/cache.rebuild:access)",
		});
		ASSERT_NO_THROW(collection.store());
		ASSERT_NO_THROW(collection.add(identity.id()));

		const datastore::AccessPolicy policy({
			.name = "name:GrpcTest.ConsumeEvent(request/cache.rebuild:access)",
			.rules =
				{
					{
						.attrs    = "attrs(request/cache.rebuild:access)",
						.resource = "resource(request/cache.rebuild:access)",
					},
				},
		});
		ASSERT_NO_THROW(policy.store());
		ASSERT_NO_THROW(policy.addCollection(collection.id()));

		const auto identityIds = policy.identities(true);
		EXPECT_EQ(1, identityIds.size());

		// Ensure cache is clear
		{
			for (const auto &id : identityIds) {
				for (const auto &rule : policy.rules()) {
					const datastore::AccessPolicy::Cache cache({
						.identity = id,
						.policy   = policy.id(),
						.rule     = rule,
					});

					ASSERT_NO_THROW(cache.discard());
				}
			}
		}

		grpc::CallbackServerContext           ctx;
		grpc::testing::DefaultReactorTestPeer peer(&ctx);
		gk::v1::ConsumeEventResponse          response;

		gk::v1::RebuildAccessCacheEventPayload payload;
		payload.add_ids(policy.id());

		gk::v1::Event request;
		request.set_name("request/cache.rebuild:access");

		auto any = request.mutable_payload();
		any->PackFrom(payload);

		auto reactor = service.ConsumeEvent(&ctx, &request, &response);
		EXPECT_TRUE(peer.test_status_set());
		EXPECT_TRUE(peer.test_status().ok());
		EXPECT_EQ(peer.reactor(), reactor);

		// Expect cache to be rebuilt
		{
			for (const auto &id : identityIds) {
				for (const auto &rule : policy.rules()) {
					const auto policies = datastore::AccessPolicy::Cache::check(id, rule.resource);

					ASSERT_EQ(1, policies.size());
					EXPECT_EQ(policy.id(), policies[0].id);
					EXPECT_EQ(rule.attrs, policies[0].attrs);
				}
			}
		}
	}

	// Success: request/cache.rebuild:rbac
	{
		const datastore::Identity identity({
			.sub = "sub:GrpcTest.ConsumeEvent(request/cache.rebuild:rbac)",
		});
		ASSERT_NO_THROW(identity.store());

		const datastore::Collection collection({
			.name = "name:GrpcTest.ConsumeEvent(request/cache.rebuild:rbac)",
		});
		ASSERT_NO_THROW(collection.store());
		ASSERT_NO_THROW(collection.add(identity.id()));

		const datastore::Role role({
			.name = "name:GrpcTest.ConsumeEvent(request/cache.rebuild:rbac)",
			.permissions =
				{
					{"permissions[0]:GrpcTest.ConsumeEvent(request/cache.rebuild:rbac)"},
				},
		});
		ASSERT_NO_THROW(role.store());

		const datastore::RbacPolicy policy({
			.name = "name:GrpcTest.ConsumeEvent(request/cache.rebuild:rbac)",
		});
		ASSERT_NO_THROW(policy.store());

		const datastore::RbacPolicy::Rule rule({
			.attrs  = R"({"key": "value"})",
			.roleId = role.id(),
		});
		ASSERT_NO_THROW(policy.addRule(rule));

		ASSERT_NO_THROW(policy.addCollection(collection.id()));

		const auto identityIds = policy.identities(true);
		EXPECT_EQ(1, identityIds.size());

		// Ensure cache is clear
		{
			for (const auto &id : identityIds) {
				for (const auto &perm : role.permissions()) {
					const datastore::RbacPolicy::Cache cache({
						.identity   = id,
						.permission = perm,
						.policy     = policy.id(),
						.rule       = rule,
					});

					ASSERT_NO_THROW(cache.discard());
				}
			}
		}

		grpc::CallbackServerContext           ctx;
		grpc::testing::DefaultReactorTestPeer peer(&ctx);
		gk::v1::ConsumeEventResponse          response;

		gk::v1::RebuildRbacCacheEventPayload payload;
		payload.add_ids(policy.id());

		gk::v1::Event request;
		request.set_name("request/cache.rebuild:rbac");

		auto any = request.mutable_payload();
		any->PackFrom(payload);

		auto reactor = service.ConsumeEvent(&ctx, &request, &response);
		EXPECT_TRUE(peer.test_status_set());
		EXPECT_TRUE(peer.test_status().ok());
		EXPECT_EQ(peer.reactor(), reactor);

		// Expect cache to be rebuilt
		{
			for (const auto &id : identityIds) {
				for (const auto &perm : role.permissions()) {
					const auto policies = datastore::RbacPolicy::Cache::check(id, perm);
					ASSERT_EQ(1, policies.size());
					EXPECT_EQ(policy.id(), policies[0].id);
					EXPECT_EQ(*rule.attrs, policies[0].attrs);
				}
			}
		}
	}
}

// Identities
TEST_F(GrpcTest, CreateIdentity) {
	service::Grpc service;

	// Success: create identity
	{
		grpc::CallbackServerContext           ctx;
		grpc::testing::DefaultReactorTestPeer peer(&ctx);
		gk::v1::Identity                      response;

		gk::v1::CreateIdentityRequest request;
		request.set_sub("sub:GrpcTest.CreateIdentity");

		auto reactor = service.CreateIdentity(&ctx, &request, &response);
		EXPECT_TRUE(peer.test_status_set());
		EXPECT_TRUE(peer.test_status().ok());
		EXPECT_EQ(peer.reactor(), reactor);
		EXPECT_EQ(request.sub(), response.sub());
		EXPECT_FALSE(response.id().empty());
		EXPECT_FALSE(response.has_attrs());
	}

	// Success: create identity with `id`
	{
		grpc::CallbackServerContext           ctx;
		grpc::testing::DefaultReactorTestPeer peer(&ctx);
		gk::v1::Identity                      response;

		gk::v1::CreateIdentityRequest request;
		request.set_id("id:GrpcTest.CreateIdentity-with_id");
		request.set_sub("sub:GrpcTest.CreateIdentity-with_id");

		auto reactor = service.CreateIdentity(&ctx, &request, &response);
		EXPECT_TRUE(peer.test_status_set());
		EXPECT_TRUE(peer.test_status().ok());
		EXPECT_EQ(peer.reactor(), reactor);
		EXPECT_EQ(request.id(), response.id());
		EXPECT_EQ(request.sub(), response.sub());
		EXPECT_FALSE(response.has_attrs());
	}

	// Success: create identity with `attrs`
	{
		grpc::CallbackServerContext           ctx;
		grpc::testing::DefaultReactorTestPeer peer(&ctx);
		gk::v1::Identity                      response;

		gk::v1::CreateIdentityRequest request;
		request.set_sub("sub:GrpcTest.CreateIdentity-with_attrs");

		const std::string attrs(R"({"foo":"bar"})");
		google::protobuf::util::JsonStringToMessage(attrs, request.mutable_attrs());

		auto reactor = service.CreateIdentity(&ctx, &request, &response);
		EXPECT_TRUE(peer.test_status_set());
		EXPECT_TRUE(peer.test_status().ok());
		EXPECT_EQ(peer.reactor(), reactor);
		EXPECT_EQ(request.sub(), response.sub());
		EXPECT_TRUE(response.has_attrs());

		std::string responseAttrs;
		google::protobuf::util::MessageToJsonString(response.attrs(), &responseAttrs);
		EXPECT_EQ(attrs, responseAttrs);
	}

	// Error: duplicate `id`
	{
		const datastore::Identity identity({
			.sub = "sub:GrpcTest.CreateIdentity-duplicate_id",
		});

		try {
			identity.store();
		} catch (const std::exception &e) {
			FAIL() << e.what();
		}

		grpc::CallbackServerContext           ctx;
		grpc::testing::DefaultReactorTestPeer peer(&ctx);
		gk::v1::Identity                      response;

		gk::v1::CreateIdentityRequest request;
		request.set_id(identity.id());
		request.set_sub("sub:GrpcTest.CreateIdentity-duplicate_id");

		auto reactor = service.CreateIdentity(&ctx, &request, &response);
		EXPECT_TRUE(peer.test_status_set());
		EXPECT_EQ(grpc::StatusCode::ALREADY_EXISTS, peer.test_status().error_code());
		EXPECT_EQ("Duplicate identity id", peer.test_status().error_message());
	}

	// Error: duplicate `sub`
	{
		const datastore::Identity identity({
			.sub = "sub:GrpcTest.CreateIdentity-duplicate",
		});
		EXPECT_NO_THROW(identity.store());

		grpc::CallbackServerContext           ctx;
		grpc::testing::DefaultReactorTestPeer peer(&ctx);
		gk::v1::Identity                      response;

		gk::v1::CreateIdentityRequest request;
		request.set_sub(identity.sub());

		auto reactor = service.CreateIdentity(&ctx, &request, &response);
		EXPECT_TRUE(peer.test_status_set());
		EXPECT_EQ(grpc::StatusCode::ALREADY_EXISTS, peer.test_status().error_code());
		EXPECT_EQ("Duplicate identity", peer.test_status().error_message());
	}
}

TEST_F(GrpcTest, RetrieveIdentity) {
	service::Grpc service;

	// Success: retrieve identity by id
	{
		const datastore::Identity identity(
			{.id = "id:GrpcTest.RetrieveIdentity", .sub = "sub:GrpcTest.RetrieveIdentity"});
		EXPECT_NO_THROW(identity.store());

		grpc::CallbackServerContext           ctx;
		grpc::testing::DefaultReactorTestPeer peer(&ctx);
		gk::v1::Identity                      response;

		gk::v1::RetrieveIdentityRequest request;
		request.set_id(identity.id());

		auto reactor = service.RetrieveIdentity(&ctx, &request, &response);
		EXPECT_TRUE(peer.test_status_set());
		EXPECT_TRUE(peer.test_status().ok());
		EXPECT_EQ(peer.reactor(), reactor);
		EXPECT_EQ(identity.id(), response.id());
		EXPECT_EQ(identity.sub(), response.sub());
		EXPECT_FALSE(response.has_attrs());
	}

	// Success: retrieve identity by id with attrs
	{
		const datastore::Identity identity({
			.attrs = R"({"flag":true})",
			.sub   = "sub:GrpcTest.RetrieveIdentity-with_attrs",
		});
		ASSERT_NO_THROW(identity.store());

		grpc::CallbackServerContext           ctx;
		grpc::testing::DefaultReactorTestPeer peer(&ctx);
		gk::v1::Identity                      response;

		gk::v1::RetrieveIdentityRequest request;
		request.set_id(identity.id());

		auto reactor = service.RetrieveIdentity(&ctx, &request, &response);
		EXPECT_TRUE(peer.test_status_set());
		EXPECT_TRUE(peer.test_status().ok());
		EXPECT_EQ(peer.reactor(), reactor);
		EXPECT_EQ(identity.id(), response.id());
		EXPECT_EQ(identity.sub(), response.sub());
		EXPECT_TRUE(response.has_attrs());

		std::string attrs;
		google::protobuf::util::MessageToJsonString(response.attrs(), &attrs);
		EXPECT_EQ(*identity.attrs(), attrs);
	}

	// Error: identity not found
	{
		grpc::CallbackServerContext           ctx;
		grpc::testing::DefaultReactorTestPeer peer(&ctx);
		gk::v1::Identity                      response;

		gk::v1::RetrieveIdentityRequest request;
		request.set_id("id:GrpcTest.RetrieveIdentity-not-found");

		auto reactor = service.RetrieveIdentity(&ctx, &request, &response);
		EXPECT_TRUE(peer.test_status_set());
		EXPECT_EQ(grpc::StatusCode::NOT_FOUND, peer.test_status().error_code());
		EXPECT_EQ("Document not found", peer.test_status().error_message());
	}
}

TEST_F(GrpcTest, LookupIdentities) {
	service::Grpc service;

	// Success: lookup identities by sub
	{
		const datastore::Identity identity(
			{.id = "id:GrpcTest.LookupIdentities", .sub = "sub:GrpcTest.LookupIdentities"});
		EXPECT_NO_THROW(identity.store());

		grpc::CallbackServerContext           ctx;
		grpc::testing::DefaultReactorTestPeer peer(&ctx);
		gk::v1::LookupIdentitiesResponse      response;

		gk::v1::LookupIdentitiesRequest request;
		request.set_sub(identity.sub());

		auto reactor = service.LookupIdentities(&ctx, &request, &response);
		EXPECT_TRUE(peer.test_status_set());
		EXPECT_TRUE(peer.test_status().ok());
		EXPECT_EQ(peer.reactor(), reactor);
		EXPECT_EQ(response.data().size(), 1);
		EXPECT_EQ(response.data()[0].id(), identity.id());
	}
}

TEST_F(GrpcTest, UpdateIndentity) {
	service::Grpc service;

	// Success: update identity sub
	{
		const datastore::Identity identity(
			{.id = "id:GrpcTest.UpdateIdentity-sub", .sub = "sub:GrpcTest.UpdateIdentity-sub"});
		ASSERT_NO_THROW(identity.store());

		grpc::CallbackServerContext           ctx;
		grpc::testing::DefaultReactorTestPeer peer(&ctx);
		gk::v1::Identity                      response;

		gk::v1::UpdateIdentityRequest request;
		request.set_id(identity.id());
		request.set_sub("sub:GrpcTest.UpdateIdentity-new");

		auto reactor = service.UpdateIdentity(&ctx, &request, &response);
		EXPECT_TRUE(peer.test_status_set());
		EXPECT_TRUE(peer.test_status().ok());
		EXPECT_EQ(peer.reactor(), reactor);

		EXPECT_EQ(request.id(), response.id());
		EXPECT_EQ(request.sub(), response.sub());
		EXPECT_FALSE(response.has_attrs());

		auto updatedIdentity = datastore::RetrieveIdentity(identity.id());
		EXPECT_EQ(request.sub(), updatedIdentity.sub());
		EXPECT_EQ(1, updatedIdentity.rev());
		EXPECT_FALSE(updatedIdentity.attrs());
	}

	// Success: update identity attrs
	{
		const datastore::Identity identity({.sub = "sub:GrpcTest.UpdateIdentity-attrs"});
		ASSERT_NO_THROW(identity.store());

		grpc::CallbackServerContext           ctx;
		grpc::testing::DefaultReactorTestPeer peer(&ctx);
		gk::v1::Identity                      response;

		gk::v1::UpdateIdentityRequest request;
		request.set_id(identity.id());
		{
			auto &attrs  = *request.mutable_attrs();
			auto &fields = *attrs.mutable_fields();

			{
				google::protobuf::Value v;
				v.set_bool_value(true);

				fields["flag"] = v;
			}

			{
				google::protobuf::Value v;
				v.set_string_value("Jane Doe");

				fields["name"] = v;
			}
		}

		auto reactor = service.UpdateIdentity(&ctx, &request, &response);
		EXPECT_TRUE(peer.test_status_set());
		EXPECT_TRUE(peer.test_status().ok());
		EXPECT_EQ(peer.reactor(), reactor);

		ASSERT_TRUE(response.has_attrs());
		auto &req = *request.mutable_attrs()->mutable_fields();
		auto &res = *response.mutable_attrs()->mutable_fields();

		EXPECT_EQ(req["flag"].bool_value(), res["flag"].bool_value());
		EXPECT_EQ(req["name"].string_value(), res["name"].string_value());

		{
			std::string_view qry = R"(
					select
						attrs->'flag' as flag,
						attrs->>'name' as name
					from identities
					where _id = $1::text;
				)";

			auto res = datastore::pg::exec(qry, identity.id());
			ASSERT_EQ(1, res.size());

			auto [flag, name] = res[0].as<bool, std::string>();
			EXPECT_EQ(req["flag"].bool_value(), flag);
			EXPECT_EQ(req["name"].string_value(), name);
		}
	}

	// Error: no fields to update
	{
		grpc::CallbackServerContext           ctx;
		grpc::testing::DefaultReactorTestPeer peer(&ctx);
		gk::v1::Identity                      response;

		gk::v1::UpdateIdentityRequest request;
		request.set_id("id:GrpcTest.UpdateIdentity-no-updates");

		auto reactor = service.UpdateIdentity(&ctx, &request, &response);
		EXPECT_TRUE(peer.test_status_set());
		EXPECT_EQ(grpc::StatusCode::INTERNAL, peer.test_status().error_code());
		EXPECT_EQ("No fields to update", peer.test_status().error_message());
	}

	// Error: identity not found
	{
		grpc::CallbackServerContext           ctx;
		grpc::testing::DefaultReactorTestPeer peer(&ctx);
		gk::v1::Identity                      response;

		gk::v1::UpdateIdentityRequest request;
		request.set_id("id:GrpcTest.UpdateIdentity-not-found");
		request.set_sub("name:GrpcTest.UpdateIdentity-not-found");

		auto reactor = service.UpdateIdentity(&ctx, &request, &response);
		EXPECT_TRUE(peer.test_status_set());
		EXPECT_EQ(grpc::StatusCode::NOT_FOUND, peer.test_status().error_code());
		EXPECT_EQ("Document not found", peer.test_status().error_message());
	}
}

// RBAC
TEST_F(GrpcTest, CreateRbacPolicy) {
	service::Grpc service;
	// Success: create rbac policy with `id`
	{
		grpc::CallbackServerContext           ctx;
		grpc::testing::DefaultReactorTestPeer peer(&ctx);
		gk::v1::RbacPolicy                    response;

		gk::v1::CreateRbacPolicyRequest request;
		request.set_id("id:GrpcTest.CreateRbacPolicy-id");
		request.set_name("name:GrpcTest.CreateRbacPolicy-id");

		auto reactor = service.CreateRbacPolicy(&ctx, &request, &response);
		EXPECT_TRUE(peer.test_status_set());
		EXPECT_TRUE(peer.test_status().ok());
		EXPECT_EQ(peer.reactor(), reactor);
		EXPECT_EQ(request.id(), response.id());
		EXPECT_EQ(request.name(), response.name());
	}

	// Error: duplicate `id`
	{
		const datastore::RbacPolicy policy({.name = "name:GrpcTest.CreateRbacPolicy-duplicate"});
		EXPECT_NO_THROW(policy.store());

		grpc::CallbackServerContext           ctx;
		grpc::testing::DefaultReactorTestPeer peer(&ctx);
		gk::v1::RbacPolicy                    response;

		gk::v1::CreateRbacPolicyRequest request;
		request.set_id(policy.id());
		request.set_name("name:GrpcTest.CreateRbacPolicy-duplicate");

		auto reactor = service.CreateRbacPolicy(&ctx, &request, &response);
		EXPECT_TRUE(peer.test_status_set());
		EXPECT_EQ(grpc::StatusCode::ALREADY_EXISTS, peer.test_status().error_code());
		EXPECT_EQ("Duplicate policy id", peer.test_status().error_message());
	}

	// Success: create rbac policy
	{
		const datastore::Identity identity({.sub = "sub:GrpcTest.CreateRbacPolicy"});
		ASSERT_NO_THROW(identity.store());
		auto                  permission = "permissions[0]:GrpcTest.CreateRbacRbacPolicy";
		const datastore::Role role({
			.name = "name:GrpcTest.CreateRbacPolicy",
			.permissions =
				{
					permission,
				},
		});
		ASSERT_NO_THROW(role.store());

		grpc::CallbackServerContext           ctx;
		grpc::testing::DefaultReactorTestPeer peer(&ctx);
		gk::v1::RbacPolicy                    response;

		gk::v1::CreateRbacPolicyRequest request;
		request.set_name("name:GrpcTest.CreateRbacPolicy");
		request.add_identity_ids(identity.id());

		auto rule = request.add_rules();
		rule->set_role_id(role.id());

		// expect no access before request
		{
			const auto policies = datastore::RbacPolicy::Cache::check(identity.id(), permission);
			EXPECT_EQ(0, policies.size());
		}

		auto reactor = service.CreateRbacPolicy(&ctx, &request, &response);
		EXPECT_TRUE(peer.test_status_set());
		EXPECT_TRUE(peer.test_status().ok());
		EXPECT_EQ(peer.reactor(), reactor);

		EXPECT_FALSE(response.id().empty());
		EXPECT_EQ(request.name(), response.name());
		EXPECT_EQ(identity.id(), response.identity_ids(0));
		EXPECT_EQ(role.id(), response.rules(0).role_id());

		// expect to find single policy when checking access
		{
			const auto policies = datastore::RbacPolicy::Cache::check(identity.id(), permission);
			EXPECT_EQ(1, policies.size());
		}
	}

	// Success: create an rbac policy for collection
	// all members of collection should be granted access
	{
		grpc::CallbackServerContext           ctx;
		grpc::testing::DefaultReactorTestPeer peer(&ctx);
		gk::v1::RbacPolicy                    response;

		const datastore::Identity identity({
			.sub = "sub:GrpcTest.CreateRbacPolicy-collection",
		});
		ASSERT_NO_THROW(identity.store());
		const datastore::Collection collection({
			.name = "name:GrpcTest.CreateRbacPolicy-collection",
		});
		ASSERT_NO_THROW(collection.store());
		ASSERT_NO_THROW(collection.add(identity.id()));

		auto                  permission = "permissions[0]:GrpcTest.CreateRbacPolicy-collection";
		const datastore::Role role({
			.name = "name:GrpcTest.CreateRbacPolicy",
			.permissions =
				{
					permission,
				},
		});
		ASSERT_NO_THROW(role.store());

		gk::v1::CreateRbacPolicyRequest request;
		request.set_name("name:GrpcTest.CreateRbacPolicy");
		request.add_collection_ids(collection.id());

		auto rule = request.add_rules();
		rule->set_role_id(role.id());

		// expect no access before request
		{
			const auto policies = datastore::RbacPolicy::Cache::check(identity.id(), permission);
			EXPECT_EQ(0, policies.size());
		}

		// create access policy
		auto reactor = service.CreateRbacPolicy(&ctx, &request, &response);
		EXPECT_TRUE(peer.test_status_set());
		EXPECT_TRUE(peer.test_status().ok());
		EXPECT_EQ(peer.reactor(), reactor);

		EXPECT_FALSE(response.id().empty());
		EXPECT_EQ(request.name(), response.name());
		EXPECT_EQ(collection.id(), response.collection_ids(0));
		EXPECT_EQ(role.id(), response.rules(0).role_id());

		// expect to find single policy when checking access
		{
			const auto policies = datastore::RbacPolicy::Cache::check(identity.id(), permission);
			EXPECT_EQ(1, policies.size());
		}
	}

	// FIXME: nested collections
}

// Roles
TEST_F(GrpcTest, CreateRole) {
	service::Grpc service;

	// Success: create role
	{
		grpc::CallbackServerContext           ctx;
		grpc::testing::DefaultReactorTestPeer peer(&ctx);
		gk::v1::Role                          response;

		gk::v1::CreateRoleRequest request;
		request.set_name("name:GrpcTest.CreateRole");
		request.add_permissions("permissions[0]:GrpcTest.CreateRole");

		auto reactor = service.CreateRole(&ctx, &request, &response);
		EXPECT_TRUE(peer.test_status_set());
		EXPECT_TRUE(peer.test_status().ok());
		EXPECT_EQ(peer.reactor(), reactor);

		EXPECT_FALSE(response.id().empty());
		EXPECT_EQ(request.name(), response.name());
		for (int i = 0; i < request.permissions_size(); i++) {
			EXPECT_EQ(request.permissions(i), response.permissions(i));
		}
	}
}

TEST_F(GrpcTest, RetrieveRole) {
	service::Grpc service;

	// Success: retrieve role
	{
		const datastore::Role role({
			.id   = "id:GrpcTest.RetrieveRole",
			.name = "name:GrpcTest.RetrieveRole",
			.permissions =
				{
					{"permissions[0]:GrpcTest.RetrieveRole"},
					{"permissions[1]:GrpcTest.RetrieveRole"},
				},
		});
		ASSERT_NO_THROW(role.store());

		grpc::CallbackServerContext           ctx;
		grpc::testing::DefaultReactorTestPeer peer(&ctx);
		gk::v1::Role                          response;

		gk::v1::RetrieveRoleRequest request;
		request.set_id(role.id());

		auto reactor = service.RetrieveRole(&ctx, &request, &response);
		EXPECT_TRUE(peer.test_status_set());
		EXPECT_TRUE(peer.test_status().ok());
		EXPECT_EQ(peer.reactor(), reactor);

		EXPECT_EQ(role.id(), response.id());
		EXPECT_EQ(role.name(), response.name());

		const auto &perms = role.permissions();
		ASSERT_EQ(perms.size(), response.permissions_size());
		for (int i = 0; i < response.permissions_size(); i++) {
			EXPECT_EQ(1, perms.count(response.permissions(i)));
		}
	}
}
