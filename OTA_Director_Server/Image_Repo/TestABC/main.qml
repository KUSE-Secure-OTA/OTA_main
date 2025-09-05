// "v0.0.1"
import QtQuick 2.12
import QtQuick.Window 2.12

Window {
    width: 640
    height: 480
    visible: true
    title: qsTr("Hello World")

    // Column to arrange items vertically
    Column {
        anchors.centerIn: parent

        // First image
        Image {
            source: "./images/hyundai_front.jpg"
            width: 400
            height: 150
        }

        // Second image
        Image {
            source: "./images/aston_logo.png"
            width: 400
            height: 150
        }

        // Third image
        Image {
            source: "./images/lambo_back.jpg"
            width: 400
            height: 150
        }
    }
}
