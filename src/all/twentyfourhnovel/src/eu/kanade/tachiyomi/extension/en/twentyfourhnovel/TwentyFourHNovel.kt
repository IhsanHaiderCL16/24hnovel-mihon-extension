package eu.kanade.tachiyomi.extension.en.twentyfourhnovel

import eu.kanade.tachiyomi.network.GET
import eu.kanade.tachiyomi.source.SourceFactory
import eu.kanade.tachiyomi.source.model.FilterList
import eu.kanade.tachiyomi.source.model.MangasPage
import eu.kanade.tachiyomi.source.model.Page
import eu.kanade.tachiyomi.source.model.SChapter
import eu.kanade.tachiyomi.source.model.SManga
import eu.kanade.tachiyomi.source.online.HttpSource
import eu.kanade.tachiyomi.util.asJsoup
import okhttp3.Request
import okhttp3.Response
import java.net.URLEncoder

class TwentyFourHNovel : SourceFactory {
    override fun createSources() = listOf(TwentyFourHNovelSource())
}

class TwentyFourHNovelSource : HttpSource() {

    override val name = "24hNovel"
    override val baseUrl = "https://24hnovel.com"
    override val lang = "en"
    override val supportsLatest = true

    // --- Popular (we use the site's COMICS tag page) ---
    override fun popularMangaRequest(page: Int): Request =
        GET(comicsUrl(page), headers)

    override fun popularMangaParse(response: Response): MangasPage =
        comicsParse(response)

    // --- Latest (same page, but order by "Latest") ---
    override fun latestUpdatesRequest(page: Int): Request =
        GET(comicsUrl(page, orderBy = "latest"), headers)

    override fun latestUpdatesParse(response: Response): MangasPage =
        comicsParse(response)

    // --- Search ---
    override fun searchMangaRequest(page: Int, query: String, filters: FilterList): Request {
        val q = query.trim()
        val url = if (q.isBlank()) {
            comicsUrl(page)
        } else {
            val encoded = q.urlEncode()
            "$baseUrl/?s=$encoded&post_type=wp-manga&paged=$page"
        }
        return GET(url, headers)
    }

    override fun searchMangaParse(response: Response): MangasPage =
        comicsParse(response)

    // --- Details ---
    override fun mangaDetailsParse(response: Response): SManga {
        val document = response.asJsoup()

        val title = document.selectFirst("h1")?.text()?.trim().orEmpty()

        val thumb = document.selectFirst(
            "div.summary_image img, img.wp-post-image, .summary_image img, .profile-manga img",
        )?.let { img ->
            img.absUrl("data-src").ifBlank { img.absUrl("src") }
        }?.ifBlank { null }

        val description = document.selectFirst(
            "div.summary__content, div.description-summary, .summary__content, .description-summary",
        )?.text()?.trim()

        return SManga.create().apply {
            this.title = title
            this.thumbnail_url = thumb
            this.description = description
        }
    }

    // --- Chapters ---
    override fun chapterListParse(response: Response): List<SChapter> {
        val document = response.asJsoup()

        val chapterAnchors = document.select("li.wp-manga-chapter a")
            .ifEmpty { document.select("a[href*='/chapter-']") }

        val chapters = chapterAnchors.mapNotNull { a ->
            val href = a.absUrl("href").ifBlank { a.attr("href") }
            if (!href.contains("/chapter-")) return@mapNotNull null

            val name = a.text().trim()
            if (name.isBlank()) return@mapNotNull null

            SChapter.create().apply {
                this.name = name
                setUrlWithoutDomain(href)
            }
        }

        // Many sites list newest first; Mihon prefers oldest first
        return chapters.reversed()
    }

    // --- Pages (images) ---
    override fun pageListParse(response: Response): List<Page> {
        val document = response.asJsoup()

        val images = document.select(
            "div.reading-content img, .reading-content img, .page-break img, img.wp-manga-chapter-img",
        ).ifEmpty {
            document.select("img")
        }

        val urls = images.mapNotNull { img ->
            val url = img.absUrl("data-src")
                .ifBlank { img.absUrl("data-lazy-src") }
                .ifBlank { img.absUrl("src") }
                .trim()

            if (url.isBlank()) return@mapNotNull null

            val check = url.lowercase().substringBefore("?")
            if (!(check.endsWith(".jpg") ||
                    check.endsWith(".jpeg") ||
                    check.endsWith(".png") ||
                    check.endsWith(".webp"))
            ) {
                return@mapNotNull null
            }

            url
        }.distinct()

        return urls.mapIndexed { index, url ->
            Page(index, imageUrl = url)
        }
    }

    override fun imageUrlParse(response: Response): String =
        throw UnsupportedOperationException("Not used (we return Page image URLs directly).")

    // ---------------- Helpers ----------------

    private fun comicsUrl(page: Int, orderBy: String? = null): String {
        val path = buildString {
            append("$baseUrl/manga-tag/comic/")
            if (page > 1) append("page/$page/")
        }
        return if (orderBy.isNullOrBlank()) {
            path
        } else {
            "$path?m_orderby=$orderBy"
        }
    }

    private fun comicsParse(response: Response): MangasPage {
        val document = response.asJsoup()

        val mangaLinks = document.select("a[href*='/manga/']")
            .mapNotNull { a ->
                val href = a.absUrl("href").ifBlank { a.attr("href") }
                if (!href.contains("/manga/")) return@mapNotNull null
                if (href.contains("/chapter-")) return@mapNotNull null

                // Allow trailing slash but reject extra path segments.
                val after = href.substringAfter("/manga/", "").trimEnd('/')
                if (after.isBlank() || after.contains("/")) return@mapNotNull null

                val title = a.text().trim().ifBlank { a.attr("title").trim() }
                if (title.isBlank()) return@mapNotNull null

                SManga.create().apply {
                    this.title = title
                    setUrlWithoutDomain(href)
                }
            }
            .distinctBy { it.url }

        val hasNextPage = document.select("a:contains(Older Posts), a.next, a.next.page-numbers")
            .isNotEmpty()

        return MangasPage(mangaLinks, hasNextPage)
    }

    private fun String.urlEncode(): String =
        URLEncoder.encode(this, "UTF-8")
}
