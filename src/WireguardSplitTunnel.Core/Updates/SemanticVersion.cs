namespace WireguardSplitTunnel.Core.Updates;

public readonly record struct SemanticVersion(int Major, int Minor, int Patch) : IComparable<SemanticVersion>
{
    public static bool TryParseTag(string? value, out SemanticVersion version)
    {
        if (value is null || value.Length == 0 || value[0] != 'v')
        {
            version = default;
            return false;
        }

        return TryParseCore(value.AsSpan(1), out version);
    }

    public static bool TryParseNormalized(string? value, out SemanticVersion version)
    {
        if (value is null)
        {
            version = default;
            return false;
        }

        return TryParseCore(value.AsSpan(), out version);
    }

    public int CompareTo(SemanticVersion other)
    {
        var majorComparison = Major.CompareTo(other.Major);
        if (majorComparison != 0)
        {
            return majorComparison;
        }

        var minorComparison = Minor.CompareTo(other.Minor);
        return minorComparison != 0 ? minorComparison : Patch.CompareTo(other.Patch);
    }

    public override string ToString() => $"{Major}.{Minor}.{Patch}";

    private static bool TryParseCore(ReadOnlySpan<char> value, out SemanticVersion version)
    {
        version = default;
        var index = 0;
        if (!TryParseComponent(value, ref index, out var major)
            || !TryParseComponent(value, ref index, out var minor)
            || !TryParseComponent(value, ref index, out var patch)
            || index != value.Length)
        {
            return false;
        }

        version = new SemanticVersion(major, minor, patch);
        return true;
    }

    private static bool TryParseComponent(ReadOnlySpan<char> value, ref int index, out int component)
    {
        component = 0;
        var start = index;
        if (start >= value.Length || value[start] < '0' || value[start] > '9')
        {
            return false;
        }

        if (value[start] == '0')
        {
            index++;
            if (index < value.Length && value[index] is >= '0' and <= '9')
            {
                return false;
            }
        }
        else
        {
            while (index < value.Length && value[index] is >= '0' and <= '9')
            {
                var digit = value[index] - '0';
                if (component > (int.MaxValue - digit) / 10)
                {
                    return false;
                }

                component = (component * 10) + digit;
                index++;
            }
        }

        if (index == value.Length)
        {
            return start != 0;
        }

        if (value[index] != '.')
        {
            return false;
        }

        index++;
        return true;
    }
}
