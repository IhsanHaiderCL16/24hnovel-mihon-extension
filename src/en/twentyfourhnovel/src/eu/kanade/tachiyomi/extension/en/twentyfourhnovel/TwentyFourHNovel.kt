package eu.kanade.tachiyomi.extension.en.twentyfourhnovel

import eu.kanade.tachiyomi.network.GET
import eu.kanade.tachiyomi.source.model.Filter
import eu.kanade.tachiyomi.source.model.FilterList
import eu.kanade.tachiyomi.source.model.MangasPage
import eu.kanade.tachiyomi.source.model.Page
import eu.kanade.tachiyomi.source.model.SChapter
import eu.kanade.tachiyomi.source.model.SManga
import eu.kanade.tachiyomi.source.online.ParsedHttpSource
import okhttp3.HttpUrl.Companion.toHttpUrl
import okhttp3.Request
import okhttp3.Response
import org.jsoup.nodes.Document
import org.jsoup.nodes.Element
import java.text.SimpleDateFormat
import java.util.Locale

class TwentyFourHNovel : ParsedHttpSource() {

    override val name = "24hNovel"
    override val baseUrl = "https://24hnovel.com"
    override val lang = "en"
    override val supportsLatest = true

    // Popular Manga
    override fun popularMangaRequest(page: Int): Request {
        val url = if (page == 1) {
            "$baseUrl/manga-tag/comic/?m_orderby=views"
        } else {
            "$baseUrl/manga-tag/comic/page/$page/?m_orderby=views"
        }
        return GET(url, headers)
    }

    override fun popularMangaSelector() = "div.page-item-detail"

    override fun popularMangaFromElement(element: Element): SManga {
        return SManga.create().apply {
            element.select("h3 a, h5 a, div.post-title a").first()?.let { a ->
                setUrlWithoutDomain(a.attr("href"))
                title = a.text().trim()
            }
            thumbnail_url = element.select("img").first()?.let { img ->
                img.attr("data-src").ifBlank {
                    img.attr("data-lazy-src").ifBlank {
                        img.attr("src")
                    }
                }
            }
        }
    }

    override fun popularMangaNextPageSelector() = "a.next.page-numbers, div.nav-previous a"

    override fun popularMangaParse(response: Response): MangasPage {
        val document = response.asJsoup()
        val mangas = document.select(popularMangaSelector()).map { element ->
            popularMangaFromElement(element)
        }
        val hasNextPage = document.select(popularMangaNextPageSelector()).isNotEmpty()
        return MangasPage(mangas, hasNextPage)
    }

    // Latest Manga
    override fun latestUpdatesRequest(page: Int): Request {
        val url = if (page == 1) {
            "$baseUrl/manga-tag/comic/?m_orderby=latest"
        } else {
            "$baseUrl/manga-tag/comic/page/$page/?m_orderby=latest"
        }
        return GET(url, headers)
    }

    override fun latestUpdatesSelector() = popularMangaSelector()
    override fun latestUpdatesFromElement(element: Element) = popularMangaFromElement(element)
    override fun latestUpdatesNextPageSelector() = popularMangaNextPageSelector()

    override fun latestUpdatesParse(response: Response): MangasPage {
        val document = response.asJsoup()
        val mangas = document.select(latestUpdatesSelector()).map { element ->
            latestUpdatesFromElement(element)
        }
        val hasNextPage = document.select(latestUpdatesNextPageSelector()).isNotEmpty()
        return MangasPage(mangas, hasNextPage)
    }

    // Search Manga
    override fun searchMangaRequest(page: Int, query: String, filters: FilterList): Request {
        val url = if (page == 1) {
            "$baseUrl/manga-tag/comic/".toHttpUrl().newBuilder()
        } else {
            "$baseUrl/manga-tag/comic/page/$page/".toHttpUrl().newBuilder()
        }

        if (query.isNotBlank()) {
            url.addQueryParameter("s", query)
            url.addQueryParameter("post_type", "wp-manga")
        }

        filters.forEach { filter ->
            when (filter) {
                is OrderByFilter -> {
                    if (filter.state != 0) {
                        url.addQueryParameter("m_orderby", filter.toUriPart())
                    }
                }
                is StatusFilter -> {
                    if (filter.state != 0) {
                        url.addQueryParameter("status[]", filter.toUriPart())
                    }
                }
                is GenreFilter -> {
                    filter.state
                        .filter { it.state }
                        .forEach { url.addQueryParameter("genre[]", it.id) }
                }
                else -> {}
            }
        }

        return GET(url.toString(), headers)
    }

    override fun searchMangaSelector() = popularMangaSelector()
    override fun searchMangaFromElement(element: Element) = popularMangaFromElement(element)
    override fun searchMangaNextPageSelector() = popularMangaNextPageSelector()

    override fun searchMangaParse(response: Response): MangasPage {
        val document = response.asJsoup()
        val mangas = document.select(searchMangaSelector()).map { element ->
            searchMangaFromElement(element)
        }
        val hasNextPage = document.select(searchMangaNextPageSelector()).isNotEmpty()
        return MangasPage(mangas, hasNextPage)
    }

    // Manga Details
    override fun mangaDetailsParse(document: Document): SManga {
        return SManga.create().apply {
            title = document.selectFirst("div.post-title h1, h1")?.text()?.trim() ?: ""

            thumbnail_url = document.selectFirst("div.summary_image img")?.let { img ->
                img.attr("data-src").ifBlank {
                    img.attr("data-lazy-src").ifBlank {
                        img.attr("src")
                    }
                }
            }

            description = document.selectFirst("div.summary__content p, div.description-summary p")
                ?.text()?.trim()

            author = document.select("div.author-content a").joinToString { it.text() }

            status = when (document.selectFirst("div.post-status div.summary-content")?.text()?.trim()) {
                "OnGoing" -> SManga.ONGOING
                "Completed" -> SManga.COMPLETED
                else -> SManga.UNKNOWN
            }

            genre = document.select("div.genres-content a").joinToString { it.text() }
        }
    }

    // Chapter List
    override fun chapterListSelector() = "li.wp-manga-chapter"

    override fun chapterFromElement(element: Element): SChapter {
        return SChapter.create().apply {
            element.select("a").first()?.let { a ->
                setUrlWithoutDomain(a.attr("href"))
                name = a.text().trim()
            }

            date_upload = element.select("span.chapter-release-date").first()?.text()?.let {
                parseChapterDate(it)
            } ?: 0
        }
    }

    private fun parseChapterDate(date: String): Long {
        return try {
            val format = SimpleDateFormat("MMMM dd, yyyy", Locale.ENGLISH)
            format.parse(date)?.time ?: 0
        } catch (e: Exception) {
            0
        }
    }

    // Pages
    override fun pageListParse(document: Document): List<Page> {
        val images = document.select(
            "div.reading-content img, " +
                "div.page-break img, " +
                "img.wp-manga-chapter-img",
        )

        return images.mapIndexed { index, img ->
            val imageUrl = img.attr("data-src").ifBlank {
                img.attr("data-lazy-src").ifBlank {
                    img.attr("src")
                }
            }
            Page(index, "", imageUrl)
        }
    }

    override fun imageUrlParse(document: Document): String =
        throw UnsupportedOperationException("Not used")

    // Filters
    override fun getFilterList() = FilterList(
        Filter.Header("NOTE: Ignored if using text search!"),
        Filter.Separator(),
        OrderByFilter(),
        StatusFilter(),
        GenreFilter(getGenreList()),
    )

    private class OrderByFilter : UriPartFilter(
        "Sort By",
        arrayOf(
            Pair("Default", ""),
            Pair("Latest", "latest"),
            Pair("Most Views", "views"),
            Pair("Trending", "trending"),
            Pair("New", "new-manga"),
            Pair("A-Z", "alphabet"),
            Pair("Rating", "rating"),
        ),
    )

    private class StatusFilter : UriPartFilter(
        "Status",
        arrayOf(
            Pair("All", ""),
            Pair("Ongoing", "on-going"),
            Pair("Completed", "end"),
        ),
    )

    private class GenreFilter(genres: List<Genre>) : Filter.Group<Genre>("Genres", genres)
    private class Genre(name: String, val id: String = name.lowercase()) : Filter.CheckBox(name)

    private fun getGenreList() = listOf(
        Genre("Action"),
        Genre("Adult"),
        Genre("Adventure"),
        Genre("Comedy"),
        Genre("Drama"),
        Genre("Ecchi"),
        Genre("Fantasy"),
        Genre("Gender Bender"),
        Genre("Harem"),
        Genre("Historical"),
        Genre("Horror"),
        Genre("Isekai"),
        Genre("Josei"),
        Genre("Martial Arts"),
        Genre("Mature"),
        Genre("Mecha"),
        Genre("Mystery"),
        Genre("Psychological"),
        Genre("Romance"),
        Genre("School Life"),
        Genre("Sci-fi"),
        Genre("Seinen"),
        Genre("Shoujo"),
        Genre("Shounen"),
        Genre("Slice of Life"),
        Genre("Sports"),
        Genre("Supernatural"),
        Genre("Tragedy"),
        Genre("Yaoi"),
        Genre("Yuri"),
    )

    private open class UriPartFilter(displayName: String, val vals: Array<Pair<String, String>>) :
        Filter.Select<String>(displayName, vals.map { it.first }.toTypedArray()) {
        fun toUriPart() = vals[state].second
    }
}
