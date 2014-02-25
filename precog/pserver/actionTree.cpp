#include "pc_common.h"

bool readUserTrace(){
    string line;
    ifstream user_activity_file ("../mobile_files/data18_1_2014.txt");
    if (!user_activity_file.is_open())
    {
        printf("Unable to read user activity file\n");
        return 1;
    }

    while(getline(user_activity_file, line))
    {
        cout << line << "\n";
        // json parse the line
    }
    user_activity_file.close();

}

int main(){
    printf("Hello world!\n");
    // read the file "data18_1_2014.txt" from ../mobile_files
    readUserTrace();
    // read the file "Connectivity.txt" from ../mobile_files
    return 0;
}
