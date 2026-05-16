namespace Crackme;

public static class Program
{
    public static int Main(string[] args)
    {
        if (args.Length == 0)
        {
            Console.WriteLine("usage: dotnet-crackme <flag>");
            return 2;
        }
        if (FlagChecker.Verify(args[0]))
        {
            Console.WriteLine("Correct!");
            return 0;
        }
        Console.WriteLine("Nope.");
        return 1;
    }
}
