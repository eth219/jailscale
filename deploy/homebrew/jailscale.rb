# Homebrew formula template for a tap (ARCHITECTURE.md §14): brew install <you>/tap/jailscale
# Fill in the version and the sha256 values from the release's SHA256SUMS.txt.
class Jailscale < Formula
  desc "Publish a local port on the internet through your own hub, no root, no TUN"
  homepage "https://github.com/jailscale/jailscale"
  version "0.1.0"
  license "Apache-2.0"

  on_macos do
    on_arm do
      url "https://github.com/jailscale/jailscale/releases/download/v#{version}/jailscale-darwin-arm64"
      sha256 "REPLACE_WITH_SHA256"
    end
    on_intel do
      url "https://github.com/jailscale/jailscale/releases/download/v#{version}/jailscale-darwin-amd64"
      sha256 "REPLACE_WITH_SHA256"
    end
  end
  on_linux do
    on_arm do
      url "https://github.com/jailscale/jailscale/releases/download/v#{version}/jailscale-linux-arm64"
      sha256 "REPLACE_WITH_SHA256"
    end
    on_intel do
      url "https://github.com/jailscale/jailscale/releases/download/v#{version}/jailscale-linux-amd64"
      sha256 "REPLACE_WITH_SHA256"
    end
  end

  def install
    bin.install Dir["jailscale-*"].first => "jailscale"
  end

  service do
    run [opt_bin/"jailscale", "daemon"]
    keep_alive true
    log_path var/"log/jailscale.log"
    error_log_path var/"log/jailscale.log"
  end

  test do
    assert_match "jailscale", shell_output("#{bin}/jailscale version")
  end
end
