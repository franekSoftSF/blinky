using Blinky.Piv;

namespace Blinky.UnitTests;

public sealed class StatusWordTests
{
    [Fact]
    public void Success_is_recognised()
    {
        var sw = new StatusWord(0x9000);

        Assert.True(sw.IsSuccess);
        Assert.Null(sw.RetriesLeft);
        Assert.False(sw.HasMoreData);
    }

    [Theory]
    [InlineData(0x63C3, 3)]
    [InlineData(0x63C1, 1)]
    [InlineData(0x63C0, 0)]
    public void Retry_counter_is_decoded(int value, int expected)
    {
        Assert.Equal(expected, new StatusWord((ushort)value).RetriesLeft);
    }

    [Fact]
    public void Blocked_is_not_zero_retries()
    {
        // 6983 and 63C0 both mean "you are not getting in", but only one of
        // them is fixed by knowing the PIN. Collapsing them would send the user
        // to the wrong workflow.
        var blocked = new StatusWord(StatusWord.AuthenticationMethodBlocked);

        Assert.Null(blocked.RetriesLeft);
        Assert.False(blocked.IsSuccess);
    }

    [Theory]
    [InlineData(0x6100, 0x00)]
    [InlineData(0x6115, 0x15)]
    public void More_data_available_reports_the_length(int value, int expected)
    {
        var sw = new StatusWord((ushort)value);

        Assert.True(sw.HasMoreData);
        Assert.Equal(expected, sw.AvailableBytes);
    }

    [Theory]
    [InlineData(0x6A82)]
    [InlineData(0x6A88)]
    public void Empty_slot_is_not_an_error(int value)
    {
        Assert.True(new StatusWord((ushort)value).IsEmptySlot);
    }

    [Fact]
    public void Status_word_is_read_from_the_tail_of_a_response()
    {
        byte[] response = [0x01, 0x02, 0x03, 0x90, 0x00];

        Assert.Equal(0x9000, StatusWord.FromResponse(response).Value);
    }

    [Fact]
    public void A_response_without_a_status_word_is_rejected()
    {
        Assert.Throws<ArgumentException>(() => StatusWord.FromResponse([0x01]));
    }
}
