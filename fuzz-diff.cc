
volatile unsigned long counter = 0;
volatile bool envcheck = false;
char req_dir[128];
char *envvar = "REQ_DIR";
char buff[1024];

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t data_len) {
  static bool server_started = startServer();
  if(!server_started) {
    error("server not running");
  }

  // Get path from environment variable
  // from https://joequery.me/code/environment-variable-c/
  if (!envcheck) {
    if(!getenv(envvar)){
      fprintf(stderr, "The environment variable %s was not found.\n", envvar);
      exit(1);
    }
  
    // Make sure the buffer is large enough to hold the environment variable value. 
    if (snprintf(req_dir, 128, "%s", getenv(envvar)) >= 128){
      fprintf(stderr, "BUFSIZE of 128 was too small. Aborting\n");
      exit(1);
    }

    envcheck = true;
  }
  
  // Get full filename by appending counter
  printf("counter: %lu\n", counter);
  char filepath[256];
  if (snprintf(filepath, 256, "%s/%lu", getenv(envvar), counter) >= 256){
    fprintf(stderr, "BUFSIZE of 256 was too small. Aborting\n");
    exit(1);
  }
  
  // Open and read file into data and data_len
  FILE *fp = fopen(filepath, "rb");
  fseek(fp, 0, SEEK_END);
  long fsize = ftell(fp);
  fseek(fp, 0, SEEK_SET);

  fread(buff, fsize, 1, fp);
  fclose(fp);
 
  unsigned char request_sha[SHA_DIGEST_LENGTH];
  SHA1((uint8_t*) buff, (size_t) fsize, request_sha);
  std::string request_sha_str = sha1ToString(request_sha);

  std::string response_code;
  std::string response = sendRequest(buff, fsize, request_sha_str);

  ++counter;

  return -2;
}
