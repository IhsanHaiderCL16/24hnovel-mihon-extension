package eu.kanade.tachiyomi.extension.en.twentyfourhnovel

import eu.kanade.tachiyomi.source.SourceFactory
import eu.kanade.tachiyomi.source.model.FilterList
import eu.kanade.tachiyomi.source.online.HttpSource
import okhttp3.Request
import okhttp3.Response
import eu.kanade.tachiyomi.network.GET

class TwentyFourHNovel : SourceFactory {

    override fun createSources() = listOf(
        TwentyFourHNovelSource(),
    )
}

class TwentyFourHNovelSource : HttpSource() {

    override val name = "24hNovel"
    override val baseUrl = "https://24hnovel.com"
    override val lang = "en"
    override val supportsLatest = false

    // Request the default manga list (from the 'Comic' page)
    override fun popularMangaRequest(page: Int): Request {
        // Here, we're simply requesting the 'Comic' tag page
        return GET("$baseUrl/manga-tag/comic/?page=$page", headers)
    }

    // Parse the popular manga list page
    override fun popularMangaParse(response: Response): List<SManga> {
        val document = response.asJsoup() // Convert the response to a Jsoup document
        val mangaList = mutableListOf<SManga>()

        // Select all manga items on the page (adjust selector to match site structure)
        val elements = document.select("div.item")  // Assuming .item class for manga entries
        for (element in elements) {
            val manga = SManga.create()

            // Extract title, URL, and thumbnail for each manga item
            manga.title = element.select("h3 a").text() // Title in <h3><a> tag
            manga.setUrlWithoutDomain(element.select("h3 a").attr("href"))  // Link to the manga's page
            manga.thumbnail_url = element.select("img").attr("src")  // Thumbnail image

            mangaList.add(manga)
        }
        return mangaList
    }

    // Request the manga detail page (to extract more info)
    override fun mangaDetailsRequest(manga: SManga): Request {
        return GET(baseUrl + manga.url, headers)
    }

    // Parse the manga details page (for the description and other info)
    override fun mangaDetailsParse(response: Response): SManga {
        val document = response.asJsoup()
        val manga = SManga.create()

        // Extract the manga title, description, and thumbnail (image)
        manga.title = document.select("h1.novel-title").text()
        manga.description = document.select("div.novel-description").text()
        manga.thumbnail_url = document.select("div.novel-cover img").attr("src")

        return manga
    }

    // Request the chapter list for the manga (from the manga details page)
    override fun chapterListRequest(manga: SManga): Request {
        return GET(baseUrl + manga.url, headers)
    }

    // Parse the chapter list (extract the list of available chapters)
    override fun chapterListParse(response: Response): List<SChapter> {
        val document = response.asJsoup()
        val chapters = mutableListOf<SChapter>()

        // Select the chapter list elements
        val elements = document.select("div.chapter-list a")
        for (element in elements) {
            val chapter = SChapter.create()
            chapter.name = element.text()  // Chapter name
            chapter.setUrlWithoutDomain(element.attr("href"))  // Chapter URL
            chapters.add(chapter)
        }
        return chapters
    }

    // Parse the page list for a chapter (for fetching pages in the chapter)
    override fun pageListRequest(chapter: SChapter): Request {
        return GET(baseUrl + chapter.url, headers)
    }

    // Parse the pages (extract the image URLs for each page)
    override fun pageListParse(response: Response): List<String> {
        val document = response.asJsoup()
        val pages = mutableListOf<String>()

        // Select the image elements for the pages
        val elements = document.select("div.page-list img")
        for (element in elements) {
            pages.add(element.attr("src"))  // Image URL for each page
        }
        return pages
    }

    // Parse the image URL for individual pages (for chapter reading)
    override fun imageUrlParse(response: Response): String {
        val document = response.asJsoup()
        return document.select("div.page img").attr("src")  // Select the image URL
    }
}
