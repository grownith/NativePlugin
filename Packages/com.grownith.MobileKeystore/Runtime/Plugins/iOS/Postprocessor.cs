#if UNITY_IOS || UNITY_TVOS || UNITY_VISIONOS
#define UNITY_XCODE_EXTENSIONS_AVAILABLE
#endif

#if UNITY_EDITOR && UNITY_XCODE_EXTENSIONS_AVAILABLE
using UnityEditor;
using UnityEditor.Callbacks;
using UnityEditor.iOS.Xcode;

public class Postprocessor
{
    [PostProcessBuild]
    public static void OnPostprocessBuild(BuildTarget buildTarget, string pathToBuiltProject)
    {
        string projectPath = PBXProject.GetPBXProjectPath(pathToBuiltProject);
        PBXProject pbxProject = new PBXProject();
        pbxProject.ReadFromFile(projectPath);

        pbxProject.SetBuildProperty(pbxProject.ProjectGuid(), "GCC_ENABLE_OBJC_EXCEPTIONS", "YES");
        pbxProject.SetBuildProperty(pbxProject.GetUnityMainTargetGuid(), "GCC_ENABLE_OBJC_EXCEPTIONS", "YES");

        pbxProject.WriteToFile(projectPath);
    }
}
#endif