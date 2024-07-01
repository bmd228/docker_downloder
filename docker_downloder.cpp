// docker_downloder.cpp: определяет точку входа для приложения.
//

#include "docker_downloder.h"

using namespace std;
const  vector<std::string> registry = { "index.docker.io","registry.hub.docker.com", "registry.docker.io", "registry-1.docker.io", "hub.docker.com" };
const std::string default_registry = "https://"+registry[0];

bool add_packet(struct archive* a, const std::string& data, const size_t& size_dig, const std::string& filename)
{
	struct archive_entry* entry = archive_entry_new();
	archive_entry_set_pathname(entry, filename.c_str());
	//// archive_entry_set_size(entry, size);
	archive_entry_set_filetype(entry, AE_IFREG);
	archive_entry_set_perm(entry, 0644);
	archive_entry_set_size(entry, size_dig); 

	if (archive_write_header(a, entry) != ARCHIVE_OK) {
		std::cerr << "Error writing header: " << archive_error_string(a) << std::endl;
		archive_entry_free(entry);
		return false;
	}
	if (archive_write_data(a, data.c_str(), data.size()) < ARCHIVE_OK)
	{
		std::cerr << "Error writing data block: " << archive_error_string(a) << std::endl;
		return false;
	}
	archive_entry_free(entry);
	return true;
}
bool add_packet(httplib::Client& cli_blobs, const std::string& digest, const httplib::Headers& header, struct archive* a, const std::string& filename, const size_t& size_dig, const std::string& imagename)
{
	struct archive_entry* entry = archive_entry_new();
	archive_entry_set_pathname(entry, filename.c_str());
	//// archive_entry_set_size(entry, size);
	archive_entry_set_filetype(entry, AE_IFREG);
	archive_entry_set_perm(entry, 0644);
	archive_entry_set_size(entry, size_dig); 
	
	if (archive_write_header(a, entry) != ARCHIVE_OK) {
		std::cerr << "Error writing header: " << archive_error_string(a) << std::endl;
		archive_entry_free(entry);
		return false;
	}

	std::string data_uri =  default_registry + "/v2/" + imagename + "/blobs/" + digest;
	static int64_t offset = 0; // Track offset for each block
	std::cout << "Get blob:" << digest << std::endl;
	int try_count(15);
	while (1)
	{

		auto res = cli_blobs.Get(
			data_uri.c_str(), header,
			[&](const httplib::Response& response) {
				if (response.status == 200)
					return true; // return 'false' if you want to cancel the request.
				else false;
			},
			[&](const char* data, size_t data_length) {

				/*          if (outFile) {
							  outFile.write(data, data_length);
						  }*/
				if (archive_write_data(a, data, data_length) < ARCHIVE_OK)
				{
					std::cerr << "Error writing data block: " << archive_error_string(a) << std::endl;
					return false;
				}
				offset += data_length; // Update offset
				return true; // return 'false' if you want to cancel the request.
			}, [](uint64_t len, uint64_t total) {
				
				const int bar_width = 50;

				
				float progress = static_cast<float>(len) / total;
				int pos = static_cast<int>(bar_width * progress);

				
				std::cout << "\r[";
				for (int i = 0; i < bar_width; ++i) {
					if (i < pos) {
						std::cout << "=";
					}
					else if (i == pos) {
						std::cout << ">";
					}
					else {
						std::cout << " ";
					}
				}
				std::cout << "] " << int(progress * 100.0) << " %\r";
				std::cout.flush();
				return true; // return 'false' if you want to cancel the request.
			});
		if (res && res->status == 200) {
			break;
		}
		else if (try_count <= 0)
		{
			std::cerr << "Error get blob:" << digest << endl;
			archive_entry_free(entry);
			return false;
		}
		else
			std::this_thread::sleep_for(250ms);
		try_count--;
	}
	archive_entry_free(entry);
	return true;
}
std::string remove_sha256_prefix(const std::string& input) {
	const std::string prefix = "sha256:";
	if (input.find(prefix) == 0) {
		return input.substr(prefix.length());
	}
	return input; 
}
std::string remove_slashes(const std::string& input) {
	std::string result = input;
	result.erase(std::remove(result.begin(), result.end(), '/'), result.end());
	return result;
}
bool standart_manifest(httplib::Client& cli_blobs, const std::string& body, const httplib::Headers& header, const std::string& archive_name, const std::string& imagename, const std::string& tag)
{
	struct archive* a = archive_write_new();
	archive_write_set_format_pax_restricted(a);
	if (archive_write_open_filename(a, archive_name.c_str()) != ARCHIVE_OK) {
		std::cerr << "Could not open archive: " << archive_name << std::endl;
		archive_write_free(a);
		return false;
	}
	std::string digest;
	size_t size_digest(0);
	std::string real_name_layer;
	nlohmann::json manifest;
	manifest = nlohmann::json::parse(body);
	//if (manifest["mediaType"] == "application/vnd.docker.distribution.manifest.v2+json") //"application/vnd.oci.image.manifest.v1+json"
	//{


	digest = manifest["config"]["digest"];
	size_digest = manifest["config"]["size"].get<nlohmann::json::size_type>();

	// header.erase("Accept");
   //  header.emplace("Accept", manifest["config"]["mediaType"]);
	real_name_layer = remove_sha256_prefix(manifest["config"]["digest"].get<std::string>()) + ".json";
	std::cout << "Get config.json" << std::endl;
	if (!add_packet(cli_blobs, manifest["config"]["digest"], header, a, real_name_layer, size_digest, imagename))
	{
		std::cerr << "Error get config.json" << digest<<std::endl;
		return false;
	}
	nlohmann::json new_manifest;
	new_manifest["Config"] = real_name_layer;
	nlohmann::json repotags;
	repotags.emplace_back(imagename + ":" + tag);
	new_manifest["RepoTags"] = repotags;
	nlohmann::json name_layers;
	std::vector<std::future<bool>> futures;
	for (const auto& layers : manifest["layers"])
	{
		std::string real_name_layer = remove_sha256_prefix(layers["digest"].get<std::string>()) + ".gz";
		name_layers.emplace_back(real_name_layer);
		size_digest = layers["size"].get<nlohmann::json::size_type>();
		//header.erase("Accept");
		//header.emplace("Accept", layers["mediaType"]);		
		//futures.push_back(std::async(std::launch::async, static_cast<bool(*)(httplib::Client & cli_blobs, const std::string & digest, const httplib::Headers & header, struct archive* a, const std::string & filename, const size_t & size_dig, const std::string & imagename)>(&add_packet), std::ref(cli_blobs), layers["digest"], header, a, real_name_layer, size_digest, imagename));
		if (!add_packet(cli_blobs, layers["digest"], header, a, real_name_layer, size_digest, imagename))
		{
			return false;
		}

	}

	new_manifest["Layers"] = name_layers;
	std::string string_new_maifest = "[" + new_manifest.dump() + "]";
	size_digest = manifest["config"]["size"].get<nlohmann::json::size_type>();
	if (!add_packet(a, string_new_maifest, string_new_maifest.size(), "manifest.json"))
	{
		archive_write_close(a);
		archive_write_free(a);
		return false;
	}
	archive_write_close(a);
	archive_write_free(a);
	return true;
}


int main(int argc, char** argv)
{
	try
	{
	CLI::App app{ "App for downloading images from docker " };
	argv = app.ensure_utf8(argv);
	std::string imageName;
	std::string tag = "latest";
	std::string archive_path;
	std::string docker_get_path;
	bool enable_proxy = false;
	bool only_http = false;
	bool digest_auth = false;
	std::string username;
	std::string password;
	std::string ip_proxy;
	int port_proxy;
	
	app.set_config("--config","config.yaml","Read an yaml file",false)->transform(CLI::FileOnDefaultPath("config.yaml", false));;
	app.add_option("-i,--image", imageName, "Image name in repository")->configurable(false);	
	app.add_option("-t,--tag", tag, "Tag")->default_val("latest")->configurable(false);
	app.add_option("-o,--out", archive_path, "Save to")->default_val("D:/")->configurable(true);
	app.add_flag("--proxy", enable_proxy, "Enable proxy")->default_val(false)->configurable(true);
	app.add_flag("--digest", digest_auth, "Enable digest auth")->default_val(false)->configurable(true);
	app.add_option("-a,--adress", ip_proxy, "IP adress for proxy")->configurable(true);
	app.add_option("-u,--username", username, "Proxy username")->configurable(true);
	app.add_option("-k,--pwd", password, "Proxy password")->configurable(true);
	app.add_option("-p,--port", port_proxy, "Proxy port")->default_val(0)->configurable(true);
	
	CLI11_PARSE(app, argc, argv);
	std::string output_config_file = "config.yaml"; 
	std::ofstream ofs(output_config_file);
	if (ofs.is_open()) {
		ofs << app.config_to_str(true, true); 
		ofs.close();
		std::cout << "Configuration saved to " << output_config_file << std::endl;
	}
	else {
		std::cerr << "Could not open file for writing: " << output_config_file << std::endl;
	}

	if (imageName.empty() || archive_path.empty()||(enable_proxy&& (ip_proxy.empty()|| port_proxy==0)))
	{
		std::cerr<<app.help();
		return 0;
	}
	if (imageName.find('/') == std::string::npos)
		imageName = "library/" + imageName;

	

	httplib::Client cli_auth("https://auth.docker.io");
	cli_auth.set_connection_timeout(10);
	cli_auth.set_write_timeout(30);
	cli_auth.set_read_timeout(30);
	cli_auth.set_follow_location(true);

	httplib::Client cli_blobs(default_registry); //registry.hub.docker.com //registry500.docker.io
	cli_blobs.set_follow_location(true);
	cli_blobs.set_connection_timeout(10);
	cli_blobs.set_write_timeout(30);
	cli_blobs.set_read_timeout(30);
	
	if (enable_proxy)
	{
		
		cli_auth.set_proxy(ip_proxy, port_proxy);
		 cli_blobs.set_proxy(ip_proxy, port_proxy);
		 if (!username.empty() && !password.empty())
		 {
			 if (digest_auth)
			 {
				 cli_auth.set_proxy_digest_auth(username, password);
				 cli_blobs.set_proxy_digest_auth(username, password);
			 }
			 else
			 {
				 cli_auth.set_proxy_basic_auth(username, password);
				 cli_blobs.set_proxy_basic_auth(username, password);
			 }
		 }
	}

	 
	std::cout << "Downloading Docker image: " << imageName << std::endl;
	
	docker_get_path = "/token?service=registry.docker.io&scope=repository:" + imageName + ":pull";
	std::string tag_uri =  default_registry + "/v2/" + imageName + "/manifests/latest";

	httplib::Headers header;

	header.emplace("Accept", "application/vnd.docker.distribution.manifest.v2+json");
	header.emplace("Accept", "application/vnd.docker.distribution.manifest.list.v2+json");
	header.emplace("Accept", "application/vnd.docker.distribution.manifest.v1+json");
	header.emplace("Accept", "application/vnd.oci.image.manifest.v1+json");
	header.emplace("Accept", "application/vnd.oci.image.index.v1+json");
	header.emplace("Accept", "application/vnd.oci.descriptor.v1+json");

	std::cout << "Get token" << std::endl;
	int try_count(15);
	httplib::Result res;
	while (true) {
		res = cli_auth.Get(docker_get_path.c_str(), header);
		if (res && res->status == 200) {

			nlohmann::json tokenizer = nlohmann::json::parse(res->body);
			std::string token = tokenizer["token"].get<std::string>();
			std::string access_token = tokenizer["access_token"].get<std::string>();
			cli_blobs.set_bearer_token_auth(token);
			break;
		}
		else if (try_count <= 0)
		{
			std::cerr << "Failed to get token";
			return 0;
		}
		else
			std::this_thread::sleep_for(250ms);
		try_count--;
	}
	std::cout << "Get manifest" << std::endl;
	
	std::string digest;
	size_t size_digest(0);
	std::string real_name_layer;
	nlohmann::json manifest;
	while (true)
	{
		res = cli_blobs.Get(tag_uri.c_str(), header);
		if (res && res->status == 200) {
			auto content_type = res->headers.find("content-type")->second;
			if (content_type == "application/vnd.docker.distribution.manifest.v2+json")
			{
				auto archive_name = archive_path + remove_slashes(imageName) + "_" + tag + ".tar";
				if (!standart_manifest(cli_blobs, res->body, header, archive_name, imageName, tag))
				{
					std::cerr << "Error" << endl;
					return 0;
				}

			}
			else if (content_type == "application/vnd.oci.image.index.v1+json")
			{
				manifest = nlohmann::json::parse(res->body);
				for (const auto& k : manifest["manifests"])
				{
					if (k.count("platform") > 0 && k["platform"].count("architecture") > 0 && k["platform"]["architecture"] != "amd64")
						continue;
					digest = k["digest"];
					size_digest = k["size"].get<nlohmann::json::size_type>();
					real_name_layer = remove_sha256_prefix(digest) + ".json";
					tag_uri = default_registry + "/v2/" + imageName + "/manifests/" + digest;//k["digest"].get<std::string>();
					std::cout << "Get list manifest" << std::endl;

					while (true) {
						res = cli_blobs.Get(tag_uri.c_str(), header);

						if (res && res->status == 200) {
							auto archive_name = archive_path + remove_slashes(imageName) + "_" + tag + ".tar";
							if (!standart_manifest(cli_blobs, res->body, header, archive_name, imageName, tag))
							{
								std::cerr << "Error" << endl;
								return 0;
							}
							break;
						}
						else if (try_count <= 0)
						{
							std::cerr << "Error get list manifest" << std::endl;
							return 0;
						}
						else
						{
							std::this_thread::sleep_for(250ms);
						}
						try_count--;
					}
					break;
				}
			}

			else
			{
				std::cerr << "Sorry....Unknown content type" << std::endl;
				try
				{
					auto archive_name = archive_path + remove_slashes(imageName) + "_" + tag + ".tar";
					standart_manifest(cli_blobs, res->body, header, archive_name, imageName, tag);
				}
				catch (const std::exception&)
				{
					std::cerr << "No luck, and I warned you.";
					return 0;
				}
			}
			break;

		}
		else if (try_count <= 0)
		{
			std::cerr << "Failed to get a manifest";
			return 0;
		}
		else
			std::this_thread::sleep_for(250ms);
		try_count--;
	}
	}
	catch (const std::exception& e)
	{
		std::cerr << e.what()<<endl;
	}
	std::cout << "Complite docker images";
	return 0;

}
