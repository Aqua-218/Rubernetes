# frozen_string_literal: true

# A job that runs every night, with a password from a Secret and a scratch
# directory.
#
#   rubectl render -f examples/manifests/nightly_report.rb --allow-code -o yaml

cron_job "nightly-report" do
  schedule "0 3 * * *"
  concurrency_policy "Forbid"

  container "report", image: "busybox:1.36", command: ["sh", "-c", "date > /scratch/report.txt && cat /scratch/report.txt"] do
    env "DB_PASSWORD", from: secret("report-db"), key: "password"
    mount "scratch", at: "/scratch"
    memory limit: "128Mi"
  end
  volume "scratch"
end
