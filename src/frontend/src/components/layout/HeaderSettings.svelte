<script lang="ts">
  import { authState, token } from "../../data/auth.svelte";
  import { locale, locales, t } from "../../data/locale.svelte";
  import InfoDialog from "../InfoDialog.svelte";
  import Button from "../ui/Button.svelte";
  import Tooltip from "../ui/Tooltip.svelte";
  import { updater } from "../../data/updater.svelte";
  import { nav } from "../../data/nav.svelte";

  import { Info, Locale, LogOut } from "../ui/icons";

  const version = import.meta.env.VITE_PKG_VERSION || "0.0.0";
  const buildDate = import.meta.env.VITE_BUILD_DATE || "";
  const isDev =
    import.meta.env.VITE_PKG_VERSION_IS_DEV?.toLowerCase() === "true" || version === "0.0.0";

  let infoIsOpen = $state(false);

  const rotateLocale = () => {
    const keys = Object.keys(locales);
    const idx = keys.indexOf(locale.current);
    locale.current = keys[(idx + 1) % keys.length];
  };
  const flag = (key: string) => (key === "en" ? "🇺🇸" : key === "ru" ? "🇷🇺" : key);

  function logout() {
    token.reset();
  }
</script>

<div class="container">
  <div class="version">
    <Tooltip value={`${t("build")}: ${version}${buildDate ? `\n${buildDate}` : ""}`}>
      <span class="version-text">{version}{#if isDev && buildDate}{" "}({buildDate}){/if}</span>
    </Tooltip>
    {#if updater.newVersion}
      <div
        class="update-badge"
        role="button"
        tabindex="0"
        onclick={() => nav.goto("settings")}
        onkeydown={(e) => (e.key === "Enter" || e.key === " ") && nav.goto("settings")}
        title={t("New update available")}
      >
        &#8593;
      </div>
    {/if}
    {#if isDev}
      <div class="under-construction">dev</div>
    {/if}
  </div>

  <div class="info">
    <Tooltip value={t("Info about this app")}>
      <Button small onclick={() => (infoIsOpen = true)}>
        <div class="info-content">
          <Info size={16} />
          {t("Info")}
        </div>
      </Button>
    </Tooltip>
  </div>

  <div class="locale">
    <Tooltip value={t("Change Locale")}>
      <Button small onclick={rotateLocale}>
        <div class="locale-content">
          <Locale size={16} />
          {flag(locale.current)}
        </div>
      </Button>
    </Tooltip>
  </div>

  {#if authState.enabled}
    <div class="logout">
      <Tooltip value={t("Logout")}>
        <Button small onclick={logout}>
          <LogOut size={20} />
        </Button>
      </Tooltip>
    </div>
  {/if}
</div>

<InfoDialog bind:open={infoIsOpen} />

<style>
  .under-construction {
    background: repeating-linear-gradient(45deg, #ffcc00, #ffcc00 10px, #ff6600 10px, #ff6600 20px);
    color: black;
    font-weight: bold;
    padding: 4px 4px;
    border-radius: 4px;
    box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
    flex: 0 0 auto;
    margin-left: 0.5rem;
    white-space: nowrap;
  }

  .update-badge {
    background: var(--green, #28a745);
    color: white;
    font-weight: bold;
    padding: 2px 6px;
    border-radius: 4px;
    box-shadow: 0 2px 4px rgba(0, 0, 0, 0.2);
    flex: 0 0 auto;
    margin-left: 0.5rem;
    font-size: 0.8rem;
    cursor: pointer;
    transition: transform 0.1s;
  }
  .update-badge:hover {
    transform: scale(1.05);
  }

  .container {
    display: flex;
    flex-direction: row;
    align-items: center;
    gap: 0.8rem;
    min-width: 0;
    flex: 1;
  }

  .version {
    display: grid;
    grid-template-columns: minmax(0, 1fr) auto;
    align-items: center;
    flex: 1;
    min-width: 0;
  }

  .version :global(> *:first-child) {
    min-width: 0;
    display: block;
    overflow: hidden;
  }

  .version-text {
    display: block;
    font-size: smaller;
    color: var(--text-2);
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
    width: 100%;
  }

  .locale,
  .logout,
  .info {
    display: flex;
    flex-direction: row;
    align-items: center;
    flex: 0 0 auto;
  }

  .locale,
  .logout {
    gap: 1rem;
  }

  .logout :global(button),
  .locale :global(button),
  .info :global(button) {
    background: var(--bg-light);
    border-radius: 0.5rem;
    height: 35px;
  }

  .locale :global(button) {
    width: 55px;
  }

  .locale-content,
  .info-content {
    display: inline-flex;
    align-items: center;
    gap: 0.35rem;
    font-size: 1rem;
    line-height: 1;
  }

  .info-content {
    font-size: 0.85rem;
  }

  @media (max-width: 700px) {
    .locale,
    .logout {
      gap: 0.5rem;
    }

    .container {
      gap: 0.5rem;
    }
  }
</style>
