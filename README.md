# db1M // Write-ups

A Hugo security write-up blog using the [Blowfish](https://blowfish.page/) theme and an automatic GitHub Pages deployment.

## Run locally

Clone the repository with its theme submodules, then start Hugo:

```bash
git clone --recurse-submodules YOUR_REPOSITORY_URL
cd my-blog
hugo server -D
```

Open <http://localhost:1313>. The `-D` flag includes draft posts.

## Publish a write-up

Create a page bundle so screenshots can live beside the article:

```bash
hugo new content posts/my-write-up/index.md
```

Add images to the new folder and reference them with normal Markdown:

```markdown
![What the screenshot shows](screenshot.png)
```

To give the article a Blowfish thumbnail and social sharing image, add a file whose name starts with `feature`, such as `feature.png`, to the same page bundle. Blowfish discovers it automatically.

Complete the post, change `draft = true` to `draft = false`, preview it, then commit and push.

Add whatever tags describe the write-up. Homepage and archive filters are generated automatically from these values:

```toml
tags = ["Web", "CTF", "RCE"]
```

There is no fixed tag list. New tags appear in the filters as soon as a published write-up uses them.

## Deploy on GitHub Pages

1. Create a GitHub repository and push this project, including `.gitmodules`.
2. In the repository, open **Settings → Pages**.
3. Under **Build and deployment**, set **Source** to **GitHub Actions**.
4. Push to `main` or `master`. The workflow builds the correct Pages URL automatically.

Do not commit `public/`; it is generated and deployed by GitHub Actions.

## Customize later

- Site identity and author: `config/_default/languages.en.toml`
- Navigation: `config/_default/menus.en.toml`
- Blowfish features: `config/_default/params.toml`
- Accent colors and small visual tweaks: `assets/css/custom.css`

Blowfish supports per-article overrides such as `showTableOfContents`, `showHero`, `heroStyle`, and `showZenMode` in front matter when a write-up needs a different presentation.

When a GitHub remote exists, replace the placeholder `baseURL` in `config/_default/hugo.toml` with the live URL. The deployment workflow already overrides it during production builds.
