using System;
using System.Windows;
using Microsoft.Win32;

namespace Blinky.Agent.Ui;

/// <summary>Light, dark, or whatever Windows is set to.</summary>
public enum ThemeChoice
{
    System,
    Light,
    Dark,
}

/// <summary>
/// Swaps the colour dictionary under a running window.
/// </summary>
/// <remarks>
/// Following the system is the default rather than an option nobody finds. A
/// tool that stays white on a machine set to dark is the one window that
/// blinds somebody at night, and this one can appear on its own — the service
/// raises it when it wants a PIN.
/// </remarks>
public static class Theme
{
    private const string PersonalizeKey =
        @"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize";

    public static ThemeChoice Choice { get; private set; } = ThemeChoice.System;

    public static void Apply(ThemeChoice choice)
    {
        Choice = choice;

        var dark = choice switch
        {
            ThemeChoice.Light => false,
            ThemeChoice.Dark => true,
            _ => SystemPrefersDark(),
        };

        var dictionary = new ResourceDictionary
        {
            Source = new Uri(
                dark ? "Themes/Dark.xaml" : "Themes/Light.xaml", UriKind.Relative),
        };

        var resources = Application.Current.Resources.MergedDictionaries;

        // Replaced rather than appended. Appending would leave the old
        // dictionary underneath, and every DynamicResource would keep resolving
        // to whichever copy happened to be found first.
        resources.Clear();
        resources.Add(dictionary);
    }

    /// <summary>
    /// Windows keeps this as <c>AppsUseLightTheme</c>, where 0 means dark. A
    /// missing value means a machine that has never been told, and light is
    /// what those look like.
    /// </summary>
    private static bool SystemPrefersDark()
    {
        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(PersonalizeKey);

            return key?.GetValue("AppsUseLightTheme") is int light && light == 0;
        }
        catch (Exception ex) when (ex is System.Security.SecurityException
                                      or UnauthorizedAccessException)
        {
            return false;
        }
    }
}
