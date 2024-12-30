<Query Kind="Program">
  <NuGetReference>AngleSharp</NuGetReference>
  <NuGetReference>editorconfig</NuGetReference>
  <NuGetReference>Semver</NuGetReference>
  <NuGetReference>System.Interactive</NuGetReference>
  <NuGetReference>System.Interactive.Async</NuGetReference>
  <NuGetReference>System.Reactive</NuGetReference>
  <Namespace>AngleSharp.Dom</Namespace>
  <Namespace>AngleSharp.Html.Dom</Namespace>
  <Namespace>AngleSharp.Html.Parser</Namespace>
  <Namespace>EditorConfig.Core</Namespace>
  <Namespace>System.Net.Http</Namespace>
  <Namespace>System.Reactive</Namespace>
  <Namespace>System.Reactive.Disposables</Namespace>
  <Namespace>System.Reactive.Linq</Namespace>
  <Namespace>System.Reactive.Subjects</Namespace>
  <Namespace>System.Reactive.Threading.Tasks</Namespace>
  <Namespace>System.Threading.Tasks</Namespace>
</Query>

// #########################
// ####
// ####	Parses the microsoft docs for all the different rules and options and emits an editorconfig with all those values.
// ####
// #########################
async Task Main()
{
	var pathToEditorConfig = @"";
	var codeQualityUrl = "https://learn.microsoft.com/en-us/dotnet/fundamentals/code-analysis/quality-rules";
	var styleRulesUrl = "https://learn.microsoft.com/en-us/dotnet/fundamentals/code-analysis/style-rules";
	var editorConfig = EditorConfigFile.Parse(pathToEditorConfig).Sections
	.SelectMany(z => z)
	.ToLookup(z => z.Key, z => z.Value, StringComparer.OrdinalIgnoreCase);

	var styleConfigurationOptions = new List<RuleConfig>();
	var qualityRules = await getCodeQualityConfigurationRules("https://learn.microsoft.com/en-us/dotnet/fundamentals/code-analysis/code-quality-rule-options");
	var csharpFormattingOptions = await getFormattingConfigurationRules("https://learn.microsoft.com/en-us/dotnet/fundamentals/code-analysis/style-rules/csharp-formatting-options");
	var dotnetFormattingOptions = await getFormattingConfigurationRules("https://learn.microsoft.com/en-us/dotnet/fundamentals/code-analysis/style-rules/dotnet-formatting-options");
	var qualityConfigurationOptions = qualityRules.SelectMany(z => z.Value).ToArray();
	var codeRules = new List<RuleItem>();
	{
		var page = await GetHtmlContent(codeQualityUrl);
		var content = page.QuerySelector(".content");
		var table = content.QuerySelector("table");
		var tableRows = table.QuerySelector("tbody").QuerySelectorAll("tr");
		codeRules.AddRange(await tableRows
			.Select(row => HandleQualityRules(row, codeQualityUrl))
			.Concat()
			//.Take(10)
			.ToArrayAsync()
		);
	}
	{
		var page = await GetHtmlContent(styleRulesUrl);
		var content = page.QuerySelector(".content");
		var table = content.QuerySelector("table");
		var tableRows = table.QuerySelector("tbody").QuerySelectorAll("tr");
		codeRules.AddRange(await HandleStyleRules(tableRows, styleRulesUrl, styleConfigurationOptions)
			//.Take(10)
			.ToArrayAsync()
		);
	}

	codeRules = codeRules.DistinctBy(z => z.Code, StringComparer.OrdinalIgnoreCase).ToList();

	//codeRules.Dump();

	var b = new StringBuilder();

	b.AppendLine("# style options");
	foreach (var config in styleConfigurationOptions.DistinctBy(z => z.Name, StringComparer.OrdinalIgnoreCase).OrderBy(z => z.Name))
	{
		WriteOption(b, config, codeRules, editorConfig);	
	}
	b.AppendLine();

	b.AppendLine("# dotnet formatting options");
	foreach (var config in dotnetFormattingOptions.DistinctBy(z => z.Name, StringComparer.OrdinalIgnoreCase).OrderBy(z => z.Name))
	{
		WriteOption(b, config, codeRules, editorConfig);
	}

	b.AppendLine();

	b.AppendLine("# csharp formatting options");
	foreach (var config in csharpFormattingOptions.DistinctBy(z => z.Name, StringComparer.OrdinalIgnoreCase).OrderBy(z => z.Name))
	{
		WriteOption(b, config, codeRules, editorConfig);
	}

	b.AppendLine();
	// dotnet_analyzer_diagnostic.category-Style.severity = none
	b.AppendLine("# global severity");

	foreach (var config in codeRules.Select(z => z.Category).Distinct(StringComparer.OrdinalIgnoreCase).OrderBy(z => z))
	{
		b.AppendLine($"# dotnet_analyzer_diagnostic.category-{config}.severity = ");
	}
	b.AppendLine();

	foreach (var rule in codeRules.OrderBy(z => z.Code))
	{
		b.AppendLine($"# {rule.Code}: {rule.Title}");
		b.AppendLine($"dotnet_diagnostic.{rule.Code}.severity = {rule.Severity}");
		if (rule.RuleConfigs.Any())
		{
			b.AppendLine($"# Options: {string.Join(", ", rule.RuleConfigs)}");
		}
		if (qualityRules.TryGetValue(rule.Code, out var rules))
		{
			foreach (var config in rules)
			{
				//config.Dump();
				var (_, sev) = getValueAndSeverity(editorConfig[config.Name]?.FirstOrDefault());
				var def = sev?? config.Default;
				if (def is { Length: > 0 })
				{
					b.AppendLine($"dotnet_code_quality.{rule.Code}.{config.Name} = {config.Default} # {string.Join(", ", config.Values)}");
				}
				else
				{
					b.AppendLine($"# dotnet_code_quality.{rule.Code}.{config.Name} = ");
				}
			}
		}
		b.AppendLine();
		// # {code}: {desc}
		// dotnet_diagnostic.CA1062.severity = none
		// dotnet_code_quality.CAXXXX.excluded_symbol_names
	}

	b.ToString().Dump();
	await File.WriteAllTextAsync(Path.GetDirectoryName(LINQPad.Util.CurrentQueryPath) + "/.generated_editorconfig", b.ToString());

	static void WriteOption(StringBuilder b, RuleConfig config, List<RuleItem> codeRules, ILookup<string, string> editorConfig)
	{
		var (value, _) = getValueAndSeverity(editorConfig[config.Name]?.FirstOrDefault());
		b.AppendLine($"{config.Name} = {value ?? config.Default}");
		var usedBy = string.Join(", ", codeRules.Where(z => z.RuleConfigs.Contains(config.Name, StringComparer.OrdinalIgnoreCase)).Select(z => z.Code));
		if (!string.IsNullOrWhiteSpace(usedBy))
		{
			b.AppendLine($"# Applicable to: {string.Join(", ", codeRules.Where(z => z.RuleConfigs.Contains(config.Name, StringComparer.OrdinalIgnoreCase)).Select(z => z.Code))}");
		}
		b.AppendLine($"# {string.Join(", ", config.Values)}");
		b.AppendLine();
	}
	
	static (string value, string? severity) getValueAndSeverity(string? value) {
		if (value?.IndexOf(':') > -1) {
		var p = value.Split(':');
			return (p[0], p[1]);
		}
		return (value, null);
	}

}

static async Task<IHtmlDocument> GetHtmlContent(string uri)
{
	await Task.Delay(TimeSpan.FromSeconds(1));
	var pageResponse = await client.GetAsync(uri.Dump());
	return await parser.ParseDocumentAsync(await pageResponse.Content.ReadAsStreamAsync());
}
static HttpClient client = new();
static HtmlParser parser = new();


static IAsyncEnumerable<RuleItem> HandleStyleRules(IEnumerable<IElement> data, string url, List<RuleConfig> rules)
{
	return data
	.Select(row =>
	{
		var link = row.QuerySelector("td").QuerySelector("a") as AngleSharp.Html.Dom.IHtmlAnchorElement;
		var linkToGetDefault = url + link.PathName;
		return link.PathName.StartsWith("/ide", StringComparison.OrdinalIgnoreCase) ? linkToGetDefault : null;
	})
	.Where(z => z is not null)
	.Distinct()
	.Select(url => GetRuleData(url))
	.Concat();

	async IAsyncEnumerable<RuleItem> GetRuleData(string url)
	{
		var subDocument = await GetHtmlContent(url);
		var subPage = subDocument.QuerySelector(".content");
		var tables = subPage.QuerySelectorAll($"table")
			.Where(z => z.QuerySelector("th:first-child")?.TextContent.Equals("Property") == true)
			.Where(z => z.QuerySelector("th:last-child")?.TextContent.Equals("Description") != true);

		var ruleConfigurations = subPage.QuerySelectorAll($"table")
				.Where(z => z.QuerySelector("th:first-child")?.TextContent.Equals("Property") == true)
				.Where(z => z.QuerySelector("th:last-child")?.TextContent.Equals("Description") == true)
				.Select(table =>
				{

					var rows = table.QuerySelectorAll("tbody tr");
					var data = rows.ToLookup(z => z.FirstElementChild.TextContent, z => z.FirstElementChild.NextElementSibling.TextContent, StringComparer.OrdinalIgnoreCase);


					var name = data["Option name"].First();
					var @default = data["Default option value"].First();
					var values = data["Option values"].Concat(data[""]);



					return new RuleConfig(name, @default, values.ToArray());

				})
				.ToArray();


		foreach (var table in tables)
		{
			var rows = table.QuerySelectorAll("tbody tr");
			var data = rows.ToLookup(z => z.FirstElementChild.TextContent, z => z.LastElementChild.TextContent, StringComparer.OrdinalIgnoreCase);

			var category = data["Category"].First();
			var code = data["Rule ID"].First();
			var title = data["Title"].First();
			var options = data["Options"].Concat(data[""]);

			foreach (var rc in ruleConfigurations)
			{
				rules.Add(rc);
			}

			yield return new RuleItem(code, title, "warning", category, true, options.ToArray());
		}
	}

}



static IAsyncEnumerable<RuleItem> HandleQualityRules(IElement row, string url)
{
	var link = row.QuerySelector("td").QuerySelector("a") as AngleSharp.Html.Dom.IHtmlAnchorElement;

	var description = row.QuerySelectorAll("td").Last().TextContent;
	var rule = link.TextContent;
	var code = rule.Substring(0, rule.IndexOf(':'));

	if (code.StartsWith("IL3")) return AsyncEnumerable.Empty<RuleItem>();
	var linkToGetDefault = url + link.PathName;

	if (code.Contains("-", StringComparison.Ordinal))
	{
		var p = code.Split('-');
		var start = Regex.Replace(p[0], "[^0-9.]", "");
		var end = Regex.Replace(p[1], "[^0-9.]", "");
		var prefix = p[0].Replace(start, "");

		return AsyncEnumerable.Range(int.Parse(start), int.Parse(end) - int.Parse(start))
			.Select(value => $"{prefix}{value.ToString().PadLeft(start.Length)}")
			.SelectAwait(async c => await GetRuleData(c, linkToGetDefault))
			;
	}

	return GetRuleData(code, linkToGetDefault).ToAsyncEnumerable();


	async static Task<RuleItem> GetRuleData(string code, string url)
	{
		Regex CodeQuality = new Regex("""dotnet_code_quality\..*?\.([\w|_]*)""", RegexOptions.Compiled | RegexOptions.IgnoreCase | RegexOptions.Multiline);

		var subDocument = await GetHtmlContent(url);
		var subPage = subDocument.QuerySelector(".content");
		try
		{
			var table = subPage.QuerySelector($"table");
			var rows = table.QuerySelectorAll("tbody tr");
			var data = rows.ToDictionary(z => z.FirstElementChild.TextContent, z => z.LastElementChild.TextContent, StringComparer.OrdinalIgnoreCase);
			var category = data["Category"];
			var enabled = data.First(z => z.Key.StartsWith("Enabled by default", StringComparison.OrdinalIgnoreCase)).Value?.Equals("No", StringComparison.Ordinal) != true;

			var options = subDocument
			.Descendants()
			.OfType<IHtmlElement>()
			.Where(z => z.TagName.Equals("CODE", StringComparison.OrdinalIgnoreCase))
			.Select(z => z.TextContent)
			.SelectMany(z => CodeQuality.Matches(z))
			.Select(match =>
			{
				return match.Groups.Values.Last().Value;
			})
			.Distinct();



			return new RuleItem(code, data["Title"], enabled ? "warning" : "none", category, enabled, options.ToArray());
		}
		catch (Exception e)
		{
			return new RuleItem(code, "failed to load!", "fail", "", false, null);
		}
	}
}

async static Task<List<RuleConfig>> getFormattingConfigurationRules(string url)
{


	async IAsyncEnumerable<RuleConfig> GetRuleData(string url)
	{
		var subDocument = await GetHtmlContent(url);
		var subPage = subDocument.QuerySelector(".content");
		var tables = subPage.QuerySelectorAll($"table")
			.Where(z => z.QuerySelector("th:first-child")?.TextContent.Equals("Property") == true)
			.Where(z => z.QuerySelector("th:last-child")?.TextContent.Equals("Description") != true);

		foreach (var table in subPage.QuerySelectorAll($"table")
				.Where(z => z.QuerySelector("th:first-child")?.TextContent.Equals("Property") == true)
				.Where(z => z.QuerySelector("th:last-child")?.TextContent.Equals("Description") == true))
		{

			var rows = table.QuerySelectorAll("tbody tr");
			var data = rows.ToLookup(z => z.FirstElementChild.TextContent, z => z.FirstElementChild.NextElementSibling.TextContent, StringComparer.OrdinalIgnoreCase);


			var name = data["Option name"].First();
			var @default = data["Default option value"].FirstOrDefault();
			var values = data["Option values"].Concat(data[""]);



			yield return new RuleConfig(name, @default, values.ToArray());
		}
	}

	return await GetRuleData(url).ToListAsync();
}

async static Task<Dictionary<string, List<RuleConfig>>> getCodeQualityConfigurationRules(string url)
{
	var page = await GetHtmlContent(url);

	var headings = page.GetDescendants()
		.Where(z => z is IHtmlHeadingElement d && d.HasAttribute("id") && d.NextElementSibling is IHtmlTableElement)
			.OfType<IHtmlElement>()
			.Where(z => z.NextElementSibling.QuerySelector("th:first-child")?.TextContent.Equals("Description") == true)
			.Where(z => z.NextElementSibling.QuerySelector("th:last-child")?.TextContent.Equals("Configurable rules") == true)
		;

	var options = page.QuerySelectorAll($"table")
			.Where(z => z.QuerySelector("th:first-child")?.TextContent.Equals("Description") == true)
			.Where(z => z.QuerySelector("th:last-child")?.TextContent.Equals("Configurable rules") == true);

	var result = new Dictionary<string, List<RuleConfig>>(StringComparer.OrdinalIgnoreCase);

	foreach (var heading in headings)
	{
		var name = heading.TextContent;
		var option = heading.NextElementSibling;
		var config = GetRuleConfig(name);
		if (config is null)
		{
			$"Misssing configuration for {name}".Dump();
			continue;
		}
		var enabledForRules = option.QuerySelector("tbody > tr:first-child")?.LastElementChild?.TextContent.Split(' ', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries);

		foreach (var rule in enabledForRules)
		{
			if (!result.TryGetValue(rule, out var rules))
			{
				rules = result[rule] = new();
			}
			rules.Add(config);
		}
	}

	var subDocument = await GetHtmlContent("https://learn.microsoft.com/en-us/dotnet/fundamentals/code-analysis/style-rules");
	var subPage = subDocument.QuerySelector(".content");
	var tables = subPage.QuerySelectorAll($"table")
		.Where(z => z.QuerySelector("th:first-child")?.TextContent.Equals("Property") == true)
		.Where(z => z.QuerySelector("th:last-child")?.TextContent.Equals("Description") != true);


	return result;

	static RuleConfig GetRuleConfig(string name)
	{
		return (name) switch
		{
			"api_surface" => new(name, "public", new[] { "public", "internal", "friend", "all" }),
			"exclude_async_void_methods" => new(name, "false", new[] { "true", "false" }),
			"exclude_single_letter_type_parameters" => new(name, "false", new[] { "true", "false" }),
			"output_kind" => new(name, "ConsoleApplication, DynamicallyLinkedLibrary, NetModule, WindowsApplication, WindowsRuntimeApplication, WindowsRuntimeMetadata", new[] { "ConsoleApplication", "DynamicallyLinkedLibrary", "NetModule", "WindowsApplication", "WindowsRuntimeApplication", "WindowsRuntimeMetadata" }),
			"required_modifiers" => new(name, null /* show commented has no default */, new[] { "none", "static", "const", "readonly", "abstract", "virtual", "override", "sealed", "extern", "async" }),
			"exclude_extension_method_this_parameter" => new(name, "false", new[] { "true", "false" }),
			"null_check_validation_methods" => new(name, null /* show commented has no default */, Array.Empty<string>()),
			"additional_string_formatting_methods" => new(name, null /* show commented has no default */, Array.Empty<string>()),
			"excluded_type_names_with_derived_types" => new(name, null /* show commented has no default */, Array.Empty<string>()),
			"excluded_symbol_names" => new(name, null /* show commented has no default */, Array.Empty<string>()),
			"disallowed_symbol_names" => new(name, null /* show commented has no default */, Array.Empty<string>()),
			"exclude_ordefault_methods" => new(name, "false", new[] { "true", "false" }),
			"ignore_internalsvisibleto" => new(name, "true", new[] { "true", "false" }),
			_ => null
		};
	}
}

record RuleItem(string Code, string Title, string Severity, string Category, bool Enabled, string[] RuleConfigs)
{
	// dotnet_code_quality.CAXXXX.api_surface = private, internal
	// dotnet_diagnostic.CA1000.severity = none
}
record RuleConfig(string Name, string Default, string[] Values);
