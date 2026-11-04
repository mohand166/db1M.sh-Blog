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

## Public URLs

Write-ups use `/writeups/<slug>/` and labs use `/my-labs/<slug>/`.
These routes are configured in `config/_default/hugo.toml`; content folders stay unchanged.
The Write-ups archive is `/writeups/`. Existing article URLs have Hugo aliases
that redirect to the new addresses. New content automatically uses the new routes.

## Email subscriptions

The homepage and write-up/lab articles share an email signup form. Articles
preselect their content type; the homepage defaults to Everything.

Set up three feeds in follow.it using the production RSS URLs:

- Everything: `https://db1m.me/index.xml`
- Write-ups: `https://db1m.me/writeups/index.xml`
- My Labs: `https://db1m.me/my-labs/index.xml`

Copy the **action URL** from each follow.it subscription form into
`[subscriptions]` in `config/_default/params.toml`: `allAction`,
`writeupsAction`, and `labsAction`. These are public form URLs, not API keys.
The form posts the email to the selected feed's URL; follow.it handles the
confirmation and delivery. Until a URL is configured, that choice shows
“Email subscriptions are coming soon” and cannot submit.

Build and deploy the RSS changes before asking follow.it to import the feeds.
If follow.it requests ownership verification, add its supplied verification
file under `static/` at the requested path and deploy it.
