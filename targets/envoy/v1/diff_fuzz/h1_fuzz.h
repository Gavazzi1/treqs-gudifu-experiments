#pragma once

#include "source/common/common/assert.h"
#include "source/common/common/logger.h"

#include "test/fuzz/fuzz_runner.h"
#include "test/integration/capture_fuzz.pb.h"
#include "test/integration/http_integration.h"

namespace Envoy {

class H1FuzzIntegrationTest : public HttpIntegrationTest {
public:
  H1FuzzIntegrationTest(Network::Address::IpVersion version)
      : HttpIntegrationTest(Http::CodecType::HTTP1, version) {}

  void initialize() override;
  std::string replayDiff(const std::string&, const std::string&);
  const std::chrono::milliseconds max_wait_ms_{10};

private:
  Filesystem::ScopedUseMemfiles use_memfiles_{true};
};

} // namespace Envoy
