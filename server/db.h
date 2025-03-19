#pragma once 
#include <iostream>
#include <mutex>
#include <string>
#include <vector>
#include <map>

class db 
{
private:
    // Static pointer to the instance
    static db* instance_ptr;

    // Mutex to ensure thread safety
    static std::mutex mtx;
	std::mutex opr;

    // Private Constructor
    db() = default;
	
	std::map<std::string, std::vector<std::string>> bank_;
	std::map<std::string, std::string> keys_;

public:
    // Deleting the copy constructor to prevent copies
    db(const db& obj) = delete;

    // Static method to get the db instance
    static db* get_instance() {
        if (instance_ptr == nullptr) {
            std::lock_guard<std::mutex> lock(mtx);
            if (instance_ptr == nullptr) {
                instance_ptr = new db();
            }
        }
        return instance_ptr;
    }

    void save(const std::string& id, const std::string& data) {
		std::unique_lock<std::mutex> lk(opr);
		bank_[id].emplace_back(data);
    }

    void save_key(const std::string& id, const std::string& key) {
		std::unique_lock<std::mutex> lk(opr);
		keys_[id] = key;
	}	

	std::vector<std::string> get_data(const std::string& id) {
		std::unique_lock<std::mutex> lk(opr);
		return bank_[id];
	}

	std::string get_keys(const std::string& id) {
		std::unique_lock<std::mutex> lk(opr);
		return keys_[id];
	}

	void delete_id(const std::string& id) {
		std::unique_lock<std::mutex> lk(opr);
		for(auto it =  bank_.begin(); it != bank_.end();) {
			if( it->first == id) {
				it = bank_.erase(it);
			}
			else {
				it++;
			}
		}
	}

	void delete_data(const std::string& id, const std::string& data) {
		std::unique_lock<std::mutex> lk(opr);
		auto& tmp = bank_[id];
		for (std::vector<std::string>::iterator it = tmp.begin(); it != tmp.end();) {
			if (*it == data ) {
				it = tmp.erase(it);
			}
			else {
				++it;
			}
		}
	}

    void print_data_table() const {
		std::cout << "database size: " << bank_.size() << std::endl;
		for(auto i : bank_) {
			std::cout << i.first << std::endl;		
			for(auto j : i.second) {
				std::cout << j << std::endl;
			}
		}
    }
	void print_keys_table() const {
		std::cout << "database size: " << keys_.size() << std::endl;
		for(auto i : keys_) {
			std::cout << i.first << ": " << i.second << std::endl;
		}
	}
	std::string serialize_keys() const {
		std::stringstream s;
		s << keys_.size() << '\n';
		for(auto& i : keys_) {
			s << i.first << ":" << i.second << '\n';
		}
		return s.str();
	}
};

// Initialize static members
db* db::instance_ptr= nullptr;
std::mutex db::mtx;

