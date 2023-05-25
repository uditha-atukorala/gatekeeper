#pragma once

#include <pqxx/pqxx>

namespace datastore {
namespace pg {
using conn_t   = pqxx::connection;
using row_t    = pqxx::row;
using result_t = pqxx::result;
using nontxn_t = pqxx::nontransaction;

std::shared_ptr<conn_t> conn();

result_t exec(std::string_view qry);

template <typename... Args> inline result_t exec(std::string_view qry, Args &&...args) {
	nontxn_t tx(*conn());
	return tx.exec_params(pqxx::zview(qry), args...);
}

void init();
void init(const std::string &opts);
}; // namespace pg
} // namespace datastore
