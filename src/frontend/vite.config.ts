import { execSync } from "node:child_process";
import { defineConfig } from "vite";
import { svelte } from "@sveltejs/vite-plugin-svelte";
import { ViteMinifyPlugin  } from "vite-plugin-minify";

function git(command: string) {
  return execSync(command, {
    encoding: "utf8",
    stdio: ["ignore", "pipe", "ignore"],
  }).trim();
}

function resolveDevVersion() {
  try {
    const rawTag = git("git describe --tags --abbrev=0");
    const tag = rawTag.replace(/-rev\d+$/, "");
    const commitCount = Number(git(`git rev-list ${rawTag}..HEAD --count`));
    const commit = git("git rev-parse --short HEAD");
    const buildDate = git('git log -1 --date=format-local:%Y%m%d%H%M%S --format=%cd');
    const isDirty = git("git status --porcelain").length > 0;

    if (commitCount === 0 && !isDirty) {
      return tag;
    }

    const versionParts = tag.split(".").map((part) => Number(part));
    if (versionParts.length === 3 && versionParts.every((part) => Number.isFinite(part))) {
      versionParts[2] += 1;
      const prerelease = versionParts.join(".");
      return `${prerelease}~git${buildDate}.${commit}${isDirty ? "-dirty" : ""}`;
    }

    return `${tag || "dev"}~git${buildDate}.${commit}${isDirty ? "-dirty" : ""}`;
  } catch {
    return "dev";
  }
}

export default defineConfig(() => {
  const version = process.env.VITE_PKG_VERSION || resolveDevVersion();
  const isDevVersion =
    process.env.VITE_PKG_VERSION_IS_DEV ||
    (!/^\d+\.\d+\.\d+(?:[-~].*)?$/.test(version) ? "true" : "false");

  return {
    define: {
      "import.meta.env.VITE_PKG_VERSION": JSON.stringify(version),
      "import.meta.env.VITE_PKG_VERSION_IS_DEV": JSON.stringify(isDevVersion),
      "import.meta.env.VITE_BUILD_DATE": JSON.stringify(process.env.VITE_BUILD_DATE || ""),
    },
    plugins: [
      svelte({
        onwarn(warning, defaultHandler) {
          if (warning.code === "a11y_interactive_supports_focus") return;
          if (warning.code === "a11y_click_events_have_key_events") return;
          if (warning.code === "a11y_no_static_element_interactions") return;

          defaultHandler(warning);
        },
      }),
      ViteMinifyPlugin(),
    ],
    build: {
      cssTarget: "firefox115",
      emptyOutDir: true,
      target: "esnext",
      // assetsInlineLimit: 400000, // inline fonts
    },
  };
});
